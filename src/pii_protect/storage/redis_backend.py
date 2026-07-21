"""
pii_protect.storage.redis_backend
===================================
RedisStorage — a Redis-backed storage backend.

Each TokenRecord is stored as a Redis hash at key ``{key_prefix}token:{token_value}``.
The value-hash dedup index is stored as plain string keys at
``{key_prefix}hash:{scope}:{value_hash}`` -> token_value.

Requires the ``pii-shield[redis]`` extra (redis>=5, which ships the
``redis.asyncio`` client).

Author: Musaib Altaf
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any, Optional

from pii_protect.exceptions import OptionalDependencyMissingError
from pii_protect.storage.base import StorageBackend
from pii_protect.types import TokenRecord


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: bytes | str) -> bytes:
    if isinstance(data, bytes):
        data = data.decode("ascii")
    return base64.b64decode(data.encode("ascii"))


class RedisStorage(StorageBackend):
    """
    Redis storage backend for the PII vault.

    Parameters
    ----------
    url : str
        Redis connection URL, e.g. ``redis://localhost:6379/0``.
    key_prefix : str
        Prefix applied to all Redis keys pii_protect creates, to avoid
        collisions with other data in the same Redis instance.
    ttl_seconds : Optional[int]
        Optional TTL applied to stored token records (None = no expiry).
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        key_prefix: str = "pii_protect:",
        ttl_seconds: Optional[int] = None,
    ) -> None:
        self._url = url
        self._prefix = key_prefix
        self._ttl = ttl_seconds
        self._client: Any = None

    async def connect(self) -> None:
        try:
            from redis import asyncio as redis_asyncio
        except ImportError as exc:
            raise OptionalDependencyMissingError(
                "RedisStorage", "redis", "redis"
            ) from exc

        self._client = redis_asyncio.from_url(self._url, decode_responses=False)
        await self._client.ping()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def put(self, record: TokenRecord) -> None:
        client = self._require_client()
        token_key = self._token_key(record.token_value)

        # Only write if not already present (idempotent, mirrors ON CONFLICT DO NOTHING)
        exists = await client.exists(token_key)
        if exists:
            return

        mapping = {
            "entity_type": record.entity_type,
            "ciphertext": _b64e(record.ciphertext),
            "iv": _b64e(record.iv),
            "tag": _b64e(record.tag),
            "original_length": str(record.original_length),
            "value_hash": record.value_hash,
            "scope": record.scope or "",
            "access_count": str(record.access_count),
            "created_at": record.created_at.isoformat(),
        }
        await client.hset(token_key, mapping=mapping)
        if self._ttl:
            await client.expire(token_key, self._ttl)

        await client.set(
            self._hash_key(record.value_hash, record.scope), record.token_value
        )
        if self._ttl:
            await client.expire(
                self._hash_key(record.value_hash, record.scope), self._ttl
            )

    async def get(self, token_value: str) -> Optional[TokenRecord]:
        client = self._require_client()
        data = await client.hgetall(self._token_key(token_value))
        if not data:
            return None
        return self._from_redis_hash(token_value, data)

    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]:
        if not token_values:
            return {}
        client = self._require_client()
        pipe = client.pipeline()
        for t in token_values:
            pipe.hgetall(self._token_key(t))
        results = await pipe.execute()

        records: dict[str, TokenRecord] = {}
        for token_value, data in zip(token_values, results):
            if data:
                records[token_value] = self._from_redis_hash(token_value, data)
        return records

    async def find_by_value_hash(
        self, value_hash: str, scope: Optional[str]
    ) -> Optional[str]:
        client = self._require_client()
        result = await client.get(self._hash_key(value_hash, scope))
        return result.decode("utf-8") if isinstance(result, bytes) else result

    async def touch(self, token_value: str) -> None:
        client = self._require_client()
        await client.hincrby(self._token_key(token_value), "access_count", 1)

    async def delete_by_scope(self, scope: Optional[str]) -> int:
        client = self._require_client()
        pattern = f"{self._prefix}hash:{scope or '_'}:*"
        count = 0
        async for hash_key in client.scan_iter(match=pattern):
            token_value = await client.get(hash_key)
            if token_value:
                token_value = (
                    token_value.decode("utf-8")
                    if isinstance(token_value, bytes)
                    else token_value
                )
                await client.delete(self._token_key(token_value))
                count += 1
            await client.delete(hash_key)
        return count

    async def all_records(self):
        client = self._require_client()
        pattern = f"{self._prefix}token:*"
        prefix_len = len(f"{self._prefix}token:")
        async for key in client.scan_iter(match=pattern):
            data = await client.hgetall(key)
            if not data:
                continue
            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            token_value = key_str[prefix_len:]
            yield self._from_redis_hash(token_value, data)

    async def replace_ciphertext(
        self, token_value: str, ciphertext: bytes, iv: bytes, tag: bytes
    ) -> None:
        client = self._require_client()
        await client.hset(
            self._token_key(token_value),
            mapping={
                "ciphertext": _b64e(ciphertext),
                "iv": _b64e(iv),
                "tag": _b64e(tag),
            },
        )

    # ── Internal ──────────────────────────────────────────────────────────

    def _require_client(self) -> Any:
        if self._client is None:
            raise RuntimeError("RedisStorage.connect() must be called before use.")
        return self._client

    def _token_key(self, token_value: str) -> str:
        return f"{self._prefix}token:{token_value}"

    def _hash_key(self, value_hash: str, scope: Optional[str]) -> str:
        return f"{self._prefix}hash:{scope or '_'}:{value_hash}"

    def _from_redis_hash(
        self, token_value: str, data: dict[bytes, bytes]
    ) -> TokenRecord:
        def _s(key: str) -> str:
            v = (
                data[key.encode("utf-8")]
                if isinstance(next(iter(data)), bytes)
                else data[key]
            )
            return v.decode("utf-8") if isinstance(v, bytes) else v

        scope = _s("scope")
        return TokenRecord(
            token_value=token_value,
            entity_type=_s("entity_type"),
            ciphertext=_b64d(_s("ciphertext")),
            iv=_b64d(_s("iv")),
            tag=_b64d(_s("tag")),
            original_length=int(_s("original_length")),
            value_hash=_s("value_hash"),
            scope=scope or None,
            access_count=int(_s("access_count")),
            created_at=datetime.fromisoformat(_s("created_at")),
        )
