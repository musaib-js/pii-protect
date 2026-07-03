"""
pii_shield.exceptions
======================
Shared exception hierarchy for the pii_shield package.

Author: Musaib Altaf
"""

from __future__ import annotations


class PIIShieldError(Exception):
    """Base class for all pii_shield errors."""


class EngineNotInitialisedError(PIIShieldError):
    """Raised when mask/unmask is called before PIIMaskingEngine.initialise()."""


class DecryptionError(PIIShieldError):
    """Raised when AES-GCM authentication tag verification fails."""


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
