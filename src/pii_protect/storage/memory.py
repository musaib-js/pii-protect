"""
pii_shield.storage.memory
============================
InMemoryStorage — a plain-dict storage backend.

No persistence across process restarts. Useful for tests, short-lived
scripts, and unit-testing PIIMaskingEngine without external infrastructure.

Author: Musaib Altaf
"""

from __future__ import annotations

import asyncio
from typing import Optional

from pii_shield.storage.base import StorageBackend
from pii_shield.types import TokenRecord


class InMemoryStorage(StorageBackend):
    """
    Volatile, process-local storage backend backed by plain Python dicts.

    Thread/coroutine-safe via an internal asyncio.Lock. Data is lost when
    the process exits — do not use this for anything that needs to survive
    a restart.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenRecord] = {}
        self._hash_index: dict[tuple[str, Optional[str]], str] = {}
        self._lock = asyncio.Lock()

    async def put(self, record: TokenRecord) -> None:
        async with self._lock:
            if record.token_value not in self._tokens:
                self._tokens[record.token_value] = record
                self._hash_index[(record.value_hash, record.scope)] = record.token_value

    async def get(self, token_value: str) -> Optional[TokenRecord]:
        return self._tokens.get(token_value)

    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]:
        return {t: self._tokens[t] for t in token_values if t in self._tokens}

    async def find_by_value_hash(self, value_hash: str, scope: Optional[str]) -> Optional[str]:
        return self._hash_index.get((value_hash, scope))

    async def touch(self, token_value: str) -> None:
        async with self._lock:
            record = self._tokens.get(token_value)
            if record is not None:
                record.access_count += 1

    def __len__(self) -> int:
        return len(self._tokens)
