"""
pii_protect.storage.filesystem
================================
FileSystemStorage — a JSON-file-backed storage backend.

Persists the entire vault as a single JSON document on disk, written
atomically (write-to-temp + os.replace) to avoid partial writes if the
process is killed mid-write.

Concurrency model: every read and write re-reads the file from disk
first, under an in-process asyncio.Lock, before acting on it. This is
deliberate — an earlier version cached a snapshot taken at connect()
time and mutated only that in-memory copy, which meant two
FileSystemStorage instances pointed at the same file within the *same*
process (e.g. two independently-constructed PIIMaskingEngines sharing a
vault path) would silently clobber each other's writes: the second
instance's flush would overwrite the file with its own stale snapshot,
discarding whatever the first instance had written. Reloading before
every operation closes that hole for same-process siblings.

This still does not make FileSystemStorage safe for *concurrent
multi-process* writers — there is no cross-process file lock here, only
an in-process one. If you need that, use RedisStorage or PostgresStorage
instead, both of which push concurrency control down into the store
itself.

Author: Musaib Altaf
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from pii_protect.storage.base import StorageBackend
from pii_protect.types import TokenRecord


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _record_to_json(record: TokenRecord) -> dict[str, Any]:
    return {
        "token_value": record.token_value,
        "entity_type": record.entity_type,
        "ciphertext": _b64e(record.ciphertext),
        "iv": _b64e(record.iv),
        "tag": _b64e(record.tag),
        "original_length": record.original_length,
        "value_hash": record.value_hash,
        "scope": record.scope,
        "access_count": record.access_count,
        "created_at": record.created_at.isoformat(),
    }


def _record_from_json(data: dict[str, Any]) -> TokenRecord:
    return TokenRecord(
        token_value=data["token_value"],
        entity_type=data["entity_type"],
        ciphertext=_b64d(data["ciphertext"]),
        iv=_b64d(data["iv"]),
        tag=_b64d(data["tag"]),
        original_length=data["original_length"],
        value_hash=data["value_hash"],
        scope=data.get("scope"),
        access_count=data.get("access_count", 0),
        created_at=datetime.fromisoformat(data["created_at"]),
    )


class FileSystemStorage(StorageBackend):
    """
    JSON-file storage backend for the PII vault.

    Parameters
    ----------
    path : str | Path
        Path to the vault JSON file. Created (with parent directories) on
        first ``connect()`` if it doesn't already exist.
    """

    def __init__(self, path: "str | Path") -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._tokens: dict[str, TokenRecord] = {}
        self._hash_index: dict[tuple[str, Optional[str]], str] = {}
        self._connected = False

    async def connect(self) -> None:
        async with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if not self._path.exists():
                await asyncio.to_thread(self._atomic_write, {})
            await self._reload_locked()
            self._connected = True

    async def close(self) -> None:
        self._connected = False

    async def put(self, record: TokenRecord) -> None:
        async with self._lock:
            await self._reload_locked()
            if record.token_value in self._tokens:
                return
            self._tokens[record.token_value] = record
            self._hash_index[(record.value_hash, record.scope)] = record.token_value
            await self._flush_locked()

    async def get(self, token_value: str) -> Optional[TokenRecord]:
        async with self._lock:
            await self._reload_locked()
            return self._tokens.get(token_value)

    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]:
        async with self._lock:
            await self._reload_locked()
            return {t: self._tokens[t] for t in token_values if t in self._tokens}

    async def find_by_value_hash(
        self, value_hash: str, scope: Optional[str]
    ) -> Optional[str]:
        async with self._lock:
            await self._reload_locked()
            return self._hash_index.get((value_hash, scope))

    async def touch(self, token_value: str) -> None:
        async with self._lock:
            await self._reload_locked()
            record = self._tokens.get(token_value)
            if record is not None:
                record.access_count += 1
                await self._flush_locked()

    async def delete_by_scope(self, scope: Optional[str]) -> int:
        async with self._lock:
            await self._reload_locked()
            matching = [t for t, r in self._tokens.items() if r.scope == scope]
            for token_value in matching:
                del self._tokens[token_value]
            matching_keys = [k for k in self._hash_index if k[1] == scope]
            for key in matching_keys:
                del self._hash_index[key]
            if matching:
                await self._flush_locked()
            return len(matching)

    async def all_records(self):
        async with self._lock:
            await self._reload_locked()
            records = list(self._tokens.values())
        for record in records:
            yield record

    async def replace_ciphertext(
        self, token_value: str, ciphertext: bytes, iv: bytes, tag: bytes
    ) -> None:
        async with self._lock:
            await self._reload_locked()
            record = self._tokens.get(token_value)
            if record is not None:
                record.ciphertext = ciphertext
                record.iv = iv
                record.tag = tag
                await self._flush_locked()

    # ── Internal ──────────────────────────────────────────────────────────

    async def _reload_locked(self) -> None:
        """Refresh in-memory state from disk. Caller must hold self._lock."""
        raw = await asyncio.to_thread(self._path.read_text, "utf-8")
        data = json.loads(raw) if raw.strip() else {}
        self._tokens = {k: _record_from_json(v) for k, v in data.items()}
        self._hash_index = {
            (r.value_hash, r.scope): r.token_value for r in self._tokens.values()
        }

    async def _flush_locked(self) -> None:
        """Write the whole vault to disk atomically. Caller must hold self._lock."""
        payload = {k: _record_to_json(v) for k, v in self._tokens.items()}
        await asyncio.to_thread(self._atomic_write, payload)

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=f".{self._path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.replace(tmp_path, self._path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
