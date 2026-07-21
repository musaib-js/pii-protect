"""
pii_protect.exceptions
======================
Shared exception hierarchy for the pii_protect package.

Author: Musaib Altaf
"""

from __future__ import annotations


class PIIShieldError(Exception):
    """Base class for all pii_protect errors."""


class EngineNotInitialisedError(PIIShieldError):
    """Raised when mask/unmask is called before PIIMaskingEngine.initialise()."""


class DecryptionError(PIIShieldError):
    """Raised when AES-GCM authentication tag verification fails."""


class TokenCollisionError(PIIShieldError):
    """
    Raised when a newly generated token happens to collide with an
    existing stored token whose value_hash doesn't match — i.e. two
    different plaintext values hashed to the same token suffix.

    This is a safety guard, not a normal-operation error: with a 128-bit
    token suffix (see pii_protect.tokens) a real collision should never
    happen in practice. If this is ever raised, the vault's token space
    should be treated as needing investigation, not silently overwritten
    (which would corrupt the earlier value and leak it under the new
    value's token).
    """


class InvalidInputError(PIIShieldError, TypeError):
    """
    Raised when mask()/unmask()/redact() are called with a non-string
    input, instead of letting an unrelated AttributeError/TypeError leak
    out of internal string handling.
    """


class KeyRotationError(PIIShieldError):
    """
    Raised when re-encrypting the vault under a new key fails validation
    before any records have been modified (see
    PIIMaskingEngine.rotate_encryption_key). The vault is left untouched
    and the engine keeps using its current key.
    """


class StorageBackendError(PIIShieldError):
    """Raised for backend-specific storage failures (connection, I/O, etc.)."""


class StorageNotConnectedError(StorageBackendError):
    """Raised when a storage backend is used before connect() has been called."""


class OptionalDependencyMissingError(PIIShieldError):
    """
    Raised when a feature that requires an optional dependency is used
    without that dependency installed (e.g. spaCy, transformers, asyncpg, redis).

    The error message tells the caller exactly which extra to install, e.g.::

        pip install pii-shield[postgres]
    """

    def __init__(self, feature: str, extra: str, package: str) -> None:
        self.feature = feature
        self.extra = extra
        self.package = package
        super().__init__(
            f"{feature} requires the optional dependency '{package}'. "
            f"Install it with: pip install pii-shield[{extra}]"
        )
