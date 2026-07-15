"""
pii_shield
============
A pluggable, on-premise-first PII masking/unmasking/redaction library.

Public API
----------
    PIIMaskingEngine   — mask() / unmask() / redact()
    NEREngine          — multi-layer PII detection (regex, spaCy, transformer)
    EntityType         — canonical PII entity categories
    DetectedSpan        — a single detected PII span
    MaskResult, UnmaskResult, DetectedEntityInfo — result types
    AESGCMCipher        — the encryption primitive used internally

Storage backends live in ``pii_shield.storage``
(``InMemoryStorage``, ``FileSystemStorage``, ``RedisStorage``, ``PostgresStorage``).

Quick start
-----------
::

    import asyncio
    from pii_shield import PIIMaskingEngine
    from pii_shield.storage import InMemoryStorage

    async def main():
        async with PIIMaskingEngine(storage=InMemoryStorage()) as engine:
            result = await engine.mask("Email me at john@acme.com")
            print(result.masked_text)
            print(await engine.unmask(result.masked_text))
            print(engine.redact("Email me at john@acme.com"))

    asyncio.run(main())

Author: Musaib Altaf
"""

from pii_protect.crypto import AESGCMCipher
from pii_protect.engine import PIIMaskingEngine
from pii_protect.exceptions import (
    DecryptionError,
    EngineNotInitialisedError,
    OptionalDependencyMissingError,
    PIIShieldError,
    StorageBackendError,
    StorageNotConnectedError,
)
from pii_protect.ner import NEREngine
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import (
    DetectedEntityInfo,
    DetectedSpan,
    EntityType,
    MaskResult,
    TokenRecord,
    UnmaskResult,
)

__version__ = "0.1.4"

__all__ = [
    "PIIMaskingEngine",
    "NEREngine",
    "EntityType",
    "DetectedSpan",
    "TokenRecord",
    "MaskResult",
    "UnmaskResult",
    "DetectedEntityInfo",
    "AESGCMCipher",
    "DeterministicTokenGenerator",
    "PIIShieldError",
    "EngineNotInitialisedError",
    "DecryptionError",
    "StorageBackendError",
    "StorageNotConnectedError",
    "OptionalDependencyMissingError",
]
