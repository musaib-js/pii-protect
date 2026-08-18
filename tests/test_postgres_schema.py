"""
tests.test_postgres_schema
=============================
Schema resolution for PostgresStorage: explicit `schema=` arg > PII_SCHEMA
env var > "public" default. Only exercises __init__ (no live database
connection needed — asyncpg is imported lazily inside connect()).

Author: Musaib Altaf
"""

import pytest

from pii_protect.storage.postgres import PostgresStorage


@pytest.fixture(autouse=True)
def _clear_pii_schema_env(monkeypatch):
    monkeypatch.delenv("PII_SCHEMA", raising=False)


def test_defaults_to_public_when_no_arg_or_env():
    storage = PostgresStorage("postgresql://user:pass@localhost:5432/db")
    assert storage._schema == "public"


def test_uses_pii_schema_env_var_when_no_explicit_arg(monkeypatch):
    monkeypatch.setenv("PII_SCHEMA", "custom_schema")
    storage = PostgresStorage("postgresql://user:pass@localhost:5432/db")
    assert storage._schema == "custom_schema"


def test_explicit_schema_arg_overrides_env_var(monkeypatch):
    monkeypatch.setenv("PII_SCHEMA", "custom_schema")
    storage = PostgresStorage("postgresql://user:pass@localhost:5432/db", schema="explicit_schema")
    assert storage._schema == "explicit_schema"
