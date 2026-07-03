"""
pii_shield.storage.postgres
==============================
PostgresStorage — a PostgreSQL-backed storage backend.

Manages its own schema (created on ``connect()`` if it doesn't already
exist), so it works against a bare database with no prior migration
required. Uses ``asyncpg`` directly rather than an ORM to keep the
optional dependency footprint small.

Requires the ``pii-shield[postgres]`` extra (asyncpg).

Author: Musaib Altaf
"""

from __future__ import annotations

from typing import Any, Optional

from pii_shield.exceptions import OptionalDependencyMissingError
from pii_shield.storage.base import StorageBackend
from pii_shield.types import TokenRecord

_DEFAULT_SCHEMA = "pii_shield"

_CREATE_SCHEMA_SQL = """
CREATE SCHEMA IF NOT EXISTS {schema};

CREATE TABLE IF NOT EXISTS {schema}.token_map (
    token_value        text PRIMARY KEY,
    entity_type        text NOT NULL,
    ciphertext          bytea NOT NULL,
    encryption_iv       bytea NOT NULL,
    encryption_tag      bytea NOT NULL,
    original_length     integer NOT NULL,
    value_hash          text NOT NULL,
    scope               text,
    access_count        integer NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_accessed_at    timestamptz
);

CREATE INDEX IF NOT EXISTS ix_{schema}_value_hash
    ON {schema}.token_map (value_hash, scope);

CREATE TABLE IF NOT EXISTS {schema}.access_log (
    id              bigserial PRIMARY KEY,
    token_value     text NOT NULL REFERENCES {schema}.token_map(token_value),
    operation       text NOT NULL,
    actor           text NOT NULL,
    scope           text,
    accessed_at     timestamptz NOT NULL DEFAULT now()
);
"""


class PostgresStorage(StorageBackend):
    """
    PostgreSQL storage backend for the PII vault.

    Parameters
    ----------
    dsn : str
        asyncpg-compatible connection string,
        e.g. ``postgresql://user:pass@localhost:5432/mydb``.
    schema : str
        Postgres schema to create/use for pii_shield tables. Defaults to
        ``"pii_shield"`` to avoid colliding with application tables.
    min_pool_size, max_pool_size : int
        Connection pool bounds passed to ``asyncpg.create_pool``.
    """

    def __init__(
        self,
        dsn: str,
        schema: str = _DEFAULT_SCHEMA,
        min_pool_size: int = 1,
        max_pool_size: int = 10,
    ) -> None:
        self._dsn = dsn
        self._schema = schema
        self._min_pool_size = min_pool_size
        self._max_pool_size = max_pool_size
        self._pool: Any = None

    async def connect(self) -> None:
        try:
            import asyncpg
        except ImportError as exc:
            raise OptionalDependencyMissingError("PostgresStorage", "postgres", "asyncpg") from exc

        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min_pool_size, max_size=self._max_pool_size
        )
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_SCHEMA_SQL.format(schema=self._schema))

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def put(self, record: TokenRecord) -> None:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {self._schema}.token_map
                    (token_value, entity_type, ciphertext, encryption_iv,
                     encryption_tag, original_length, value_hash, scope, access_count)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1)
                ON CONFLICT (token_value) DO NOTHING
                """,
                record.token_value,
                record.entity_type,
                record.ciphertext,
                record.iv,
                record.tag,
                record.original_length,
                record.value_hash,
                record.scope,
            )

    async def get(self, token_value: str) -> Optional[TokenRecord]:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                f"SELECT * FROM {self._schema}.token_map WHERE token_value = $1",
                token_value,
            )
        return self._row_to_record(row) if row else None

    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]:
        if not token_values:
            return {}
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM {self._schema}.token_map WHERE token_value = ANY($1)",
                token_values,
            )
        return {row["token_value"]: self._row_to_record(row) for row in rows}

    async def find_by_value_hash(self, value_hash: str, scope: Optional[str]) -> Optional[str]:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            return await conn.fetchval(
                f"""
                SELECT token_value FROM {self._schema}.token_map
                WHERE value_hash = $1 AND scope IS NOT DISTINCT FROM $2
                LIMIT 1
                """,
                value_hash, scope,
            )

    async def touch(self, token_value: str) -> None:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                f"""
                UPDATE {self._schema}.token_map
                SET access_count = access_count + 1, last_accessed_at = now()
                WHERE token_value = $1
                """,
                token_value,
            )

    async def log_access(
        self,
        token_value: str,
        operation: str,
        actor: str,
        scope: Optional[str] = None,
    ) -> None:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                f"""
                INSERT INTO {self._schema}.access_log (token_value, operation, actor, scope)
                VALUES ($1, $2, $3, $4)
                """,
                token_value, operation, actor, scope,
            )

    # ── Internal ──────────────────────────────────────────────────────────

    def _require_pool(self) -> Any:
        if self._pool is None:
            raise RuntimeError("PostgresStorage.connect() must be called before use.")
        return self._pool

    def _row_to_record(self, row: Any) -> TokenRecord:
        return TokenRecord(
            token_value=row["token_value"],
            entity_type=row["entity_type"],
            ciphertext=bytes(row["ciphertext"]),
            iv=bytes(row["encryption_iv"]),
            tag=bytes(row["encryption_tag"]),
            original_length=row["original_length"],
            value_hash=row["value_hash"],
            scope=row["scope"],
            access_count=row["access_count"],
            created_at=row["created_at"],
        )
