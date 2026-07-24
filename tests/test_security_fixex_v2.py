"""
tests.test_security_fixes_v2
===============================
Regression tests for the four findings still open per the v0.1.9 retest:
V-8 (residual), V-13, V-16, V-19.

Author: Musaib Altaf
"""

import pytest

from pii_protect import EntityType, PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.ner import NEREngine
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator

salt = DeterministicTokenGenerator.generate_salt()
token_generator = DeterministicTokenGenerator(salt=salt)

FIXED_KEY = AESGCMCipher.generate_key()


def make_engine(**kwargs):
    return PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=token_generator,
        **kwargs,
    )


# ── V-8 (residual): parenthesised phone + spaced email ──────────────────


def test_v8_parenthesised_phone_is_now_detected():
    ner = NEREngine()
    spans = ner.detect("Call me at (98765)43210 please")
    assert any(s.entity_type == EntityType.PHONE for s in spans)


def test_v8_spaced_email_is_now_detected():
    ner = NEREngine()
    spans = ner.detect("Reach out to john @ acme.com for details")
    assert any(s.entity_type == EntityType.EMAIL for s in spans)


@pytest.mark.asyncio
async def test_v8_redact_no_longer_leaks_these_formats():
    async with make_engine() as engine:
        redacted = engine.redact("Call (98765)43210 or email john @ acme.com")
        assert "98765" not in redacted or "[REDACTED:PHONE]" in redacted
        assert "acme.com" not in redacted


# ── V-13: SWIFT no longer false-positives on ordinary capitalised words ─


@pytest.mark.parametrize("word", ["CHECKING", "SHIPMENT", "DEADLINE", "APPROVED"])
def test_v13_swift_does_not_match_ordinary_words_without_context(word):
    ner = NEREngine()
    spans = ner.detect(f"Status: {word}")
    assert not any(s.entity_type == EntityType.SWIFT for s in spans)


def test_v13_swift_still_matches_with_a_swift_label_nearby():
    ner = NEREngine()
    spans = ner.detect("Bank SWIFT code: DEUTDEFF")
    assert any(s.entity_type == EntityType.SWIFT for s in spans)

    spans2 = ner.detect("BIC DEUTDEFF")
    assert any(s.entity_type == EntityType.SWIFT for s in spans2)


def test_v13_swift_does_not_match_far_from_any_label():
    ner = NEREngine()
    # "SWIFT" appears in the text but far outside the context window
    text = "SWIFT " + ("x" * 40) + " CHECKING"
    spans = ner.detect(text)
    assert not any(s.entity_type == EntityType.SWIFT for s in spans)


# ── V-16: spaced Indian mobile number no longer evades entirely ────────


def test_v16_spaced_mobile_is_now_detected():
    ner = NEREngine()
    spans = ner.detect("Reach me on 98765 43210 anytime")
    matches = [s for s in spans if s.entity_type == EntityType.PHONE]
    assert matches
    # must be the FULL number, not a fragment (V-16's original failure mode)
    assert any(s.text.replace(" ", "") == "9876543210" for s in matches)


@pytest.mark.asyncio
async def test_v16_redact_removes_the_whole_spaced_number():
    async with make_engine() as engine:
        redacted = engine.redact("Reach me on 98765 43210 anytime")
        assert "98765" not in redacted
        assert "43210" not in redacted


# ── V-19: mask_dict/unmask_dict preserves the original leaf's type ──────


@pytest.mark.asyncio
async def test_v19_numeric_string_pii_round_trips_as_a_string():
    async with make_engine() as engine:
        data = {"phone": "9876543210"}  # deliberately a STRING, not an int
        masked = await engine.mask_dict(data, scope="s1")
        assert masked["phone"] != "9876543210"  # became a token

        restored = await engine.unmask_dict(masked, scope="s1")
        assert restored["phone"] == "9876543210"
        assert isinstance(restored["phone"], str)  # must NOT come back as int


@pytest.mark.asyncio
async def test_v19_leading_zero_string_is_not_corrupted():
    async with make_engine() as engine:
        # "007" as a phone-like string would lose its leading zero if
        # ever coerced to int -- must never happen.
        data = {"code": "0076543210"}
        masked = await engine.mask_dict(data, scope="s1")
        restored = await engine.unmask_dict(masked, scope="s1")
        assert restored["code"] == "0076543210"
        assert isinstance(restored["code"], str)


@pytest.mark.asyncio
async def test_v19_non_masked_numeric_string_still_round_trips_as_string():
    async with make_engine() as engine:
        data = {"id": "0012345"}  # not detected as PII -> never masked at all
        masked = await engine.mask_dict(data, scope="s1")
        assert masked["id"] == "0012345"
        restored = await engine.unmask_dict(masked, scope="s1")
        assert restored["id"] == "0012345"
        assert isinstance(restored["id"], str)
