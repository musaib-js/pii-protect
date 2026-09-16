"""
pii_protect
============
A pluggable, on-premise-first PII masking/unmasking/redaction library.

Public API
----------
    PIIMaskingEngine   — mask() / unmask() / redact()
    NEREngine          — multi-layer PII detection (regex, spaCy, transformer)
    DomainEntity       — a PII category declared in configuration
    EntityType         — canonical PII entity categories
    DetectedSpan        — a single detected PII span
    MaskResult, UnmaskResult, DetectedEntityInfo — result types
    AESGCMCipher        — the encryption primitive used internally

Storage backends live in ``pii_protect.storage``
(``InMemoryStorage``, ``FileSystemStorage``, ``RedisStorage``, ``PostgresStorage``).

Quick start
-----------
::

    import asyncio
    from pii_protect import PIIMaskingEngine
    from pii_protect.storage import InMemoryStorage

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
from pii_protect.ner import (
    DomainEntity,
    DomainEntityConfigError,
    DomainEntityLayer,
    NEREngine,
    load_domain_entities,
    register_entity_type,
)
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import (
    DetectedEntityInfo,
    DetectedSpan,
    EntityType,
    MaskResult,
    TokenRecord,
    UnmaskResult,
)

__version__ = "0.2.9"

__all__ = [
    "PIIMaskingEngine",
    "NEREngine",
    "DomainEntity",
    "DomainEntityLayer",
    "DomainEntityConfigError",
    "load_domain_entities",
    "register_entity_type",
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
