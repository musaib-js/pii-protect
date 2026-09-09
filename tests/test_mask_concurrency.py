"""
tests.test_mask_concurrency
===========================
mask() must not hold the event loop while detection runs.

Detection is synchronous CPU work — a regex sweep at best, a GLiNER or
transformer forward pass at worst (measured at 2.5s for ~1KB). Called inline
from an async def it froze the whole process for that time, so N concurrent
masks cost N x one mask and the ones at the back timed out having done no
work. These tests pin the fix: detection runs off the loop.
"""

import asyncio
import time

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator

salt = "test-salt-for-pii-shield-suite-do-not-use-in-prod"
token_generator = DeterministicTokenGenerator(salt=salt)
FIXED_KEY = AESGCMCipher.generate_key()


def _engine():
    return PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
    )


@pytest.mark.asyncio
async def test_the_loop_keeps_running_while_detection_is_slow():
    """The regression: a heartbeat coroutine must keep ticking during mask()."""
    async with _engine() as engine:
        engine._ner.detect = lambda text: (time.sleep(0.30) or [])

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        try:
            await engine.mask("Juan Dela Cruz")
        finally:
            beat.cancel()

    # Inline, the loop is frozen and ticks stays at 0.
    assert ticks > 5, f"event loop was blocked during mask() (ticks={ticks})"


@pytest.mark.asyncio
async def test_concurrent_masks_overlap_instead_of_queueing():
    """Nine masks of 0.2s each: ~0.2s overlapped, ~1.8s if serialised."""
    async with _engine() as engine:
        engine._ner.detect = lambda text: (time.sleep(0.20) or [])

        start = time.perf_counter()
        await asyncio.gather(*(engine.mask(f"Juan {i}") for i in range(9)))
        elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"masks serialised: {elapsed:.2f}s for 9 x 0.2s"
