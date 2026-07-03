"""
tests.test_engine
====================
Smoke tests for PIIMaskingEngine covering mask/unmask round-trips,
deduplication, and irreversible redact(), against both InMemoryStorage
and FileSystemStorage.

Author: Musaib Altaf
"""

import pytest
import logging

from pii_shield import PIIMaskingEngine
from pii_shield.crypto import AESGCMCipher
from pii_shield.storage import FileSystemStorage, InMemoryStorage

SAMPLE_TEXT = "Contact john.doe@acme.com or +919812345678 about GST 27AAPFU0939F1ZV."
FIXED_KEY = AESGCMCipher.generate_key()


@pytest.mark.asyncio
async def test_mask_unmask_roundtrip_memory():
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(SAMPLE_TEXT)
        assert result.token_count > 0
        assert "john.doe@acme.com" not in result.masked_text
        assert "{{EMAIL:" in result.masked_text

        restored = await engine.unmask(result.masked_text)
        assert restored == SAMPLE_TEXT


@pytest.mark.asyncio
async def test_mask_unmask_roundtrip_filesystem(tmp_path):
    vault_path = tmp_path / "vault.json"
    async with PIIMaskingEngine(storage=FileSystemStorage(vault_path), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(SAMPLE_TEXT, scope="doc-1")
        restored = await engine.unmask(result.masked_text, scope="doc-1")
        assert restored == SAMPLE_TEXT

    assert vault_path.exists()

    # Re-open against the same file and confirm the vault persisted.
    async with PIIMaskingEngine(storage=FileSystemStorage(vault_path), encryption_key=FIXED_KEY) as engine:
        restored_again = await engine.unmask(result.masked_text, scope="doc-1")
        assert restored_again == SAMPLE_TEXT


@pytest.mark.asyncio
async def test_dedup_same_value_reuses_token():
    text = "Email john@acme.com twice: john@acme.com"
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        result = await engine.mask(text, scope="doc-2")
        tokens = [e.token for e in result.entities if e.entity_type == "EMAIL"]
        assert len(tokens) == 2
        assert tokens[0] == tokens[1]  # same value -> same token


@pytest.mark.asyncio
async def test_redact_is_irreversible_and_stores_nothing():
    storage = InMemoryStorage()
    async with PIIMaskingEngine(storage=storage, encryption_key=FIXED_KEY) as engine:
        redacted = engine.redact(SAMPLE_TEXT)
        assert "john.doe@acme.com" not in redacted
        assert "[REDACTED:EMAIL]" in redacted
        assert len(storage) == 0  # redact() must never touch storage


@pytest.mark.asyncio
async def test_mask_dict_and_unmask_dict():
    data = {"contact": "john.doe@acme.com", "note": "call +919812345678"}
    async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=FIXED_KEY) as engine:
        masked = await engine.mask_dict(data)
        assert masked["contact"] != data["contact"]

        restored = await engine.unmask_dict(masked)
        assert restored == data
