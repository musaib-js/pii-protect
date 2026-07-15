"""
pii_shield.storage.base
=========================
Abstract storage backend interface. Every backend (in-memory, filesystem,
Redis, PostgreSQL, or a custom one you write) implements this contract,
which is all PIIMaskingEngine depends on. This is what makes the
underlying persistence layer pluggable rather than a hard dependency on
any one database.

To add a custom backend, subclass StorageBackend and implement the
abstract methods below.

Author: Musaib Altaf
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from pii_protect.types import TokenRecord


class StorageBackend(ABC):
    """
    Abstract base class for all pii_shield vault storage backends.

    Backends persist encrypted TokenRecords keyed by token_value, and
    support lookup-by-value-hash for within-scope deduplication.
    Encryption/decryption itself is handled by PIIMaskingEngine using
    AESGCMCipher — backends only ever see ciphertext.
    """

    async def connect(self) -> None:
        """
        Establish backend resources (connection pools, file handles, etc.).

        Optional to override — the default is a no-op, suitable for
        backends with no setup cost (e.g. InMemoryStorage).
        """
        return None

    async def close(self) -> None:
        """
        Release backend resources.

        Optional to override — the default is a no-op.
        """
        return None

    @abstractmethod
    async def put(self, record: TokenRecord) -> None:
        """
        Persist a TokenRecord. Must be idempotent for the same token_value
        (e.g. via upsert / ON CONFLICT DO NOTHING semantics).
        """
        raise NotImplementedError

    @abstractmethod
    async def get(self, token_value: str) -> Optional[TokenRecord]:
        """Retrieve a single TokenRecord by its token_value, or None if absent."""
        raise NotImplementedError

    @abstractmethod
    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]:
        """
        Retrieve multiple TokenRecords in as few round-trips as the backend
        allows. Missing tokens are simply absent from the returned dict.
        """
        raise NotImplementedError

    @abstractmethod
    async def find_by_value_hash(self, value_hash: str, scope: Optional[str]) -> Optional[str]:
        """
        Look up an existing token_value for a given value_hash within a
        scope (e.g. a document/invoice ID). Used to deduplicate repeated
        PII values within the same document instead of storing/encrypting
        them twice.
        """
        raise NotImplementedError

    @abstractmethod
    async def touch(self, token_value: str) -> None:
        """Increment the access count / update last-accessed metadata for a token."""
        raise NotImplementedError

    async def log_access(
        self,
        token_value: str,
        operation: str,
        actor: str,
        scope: Optional[str] = None,
    ) -> None:
        """
        Optional audit hook, called on every mask ('MASK') and unmask
        ('UNMASK') resolution. Default is a no-op; backends that support
        audit logging (e.g. PostgresStorage) may override this.
        """
        return None

    async def __aenter__(self) -> "StorageBackend":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
