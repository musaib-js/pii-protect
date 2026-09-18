"""
tests.test_token_entity_type
=============================
A value masked under one category and later detected as another gets a token
for the category it was actually detected as. Deduplication matches on the
value alone, so without this the first token ever minted is handed back for
every later detection, still wearing the first category's label.
"""

import asyncio

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import EntityType

FIXED_KEY = AESGCMCipher.generate_key()


# ─────────────────────────────────────────────────────────────────────────────
#  A token carries the category it was detected as
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    engine = PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key=FIXED_KEY,
        token_generator=DeterministicTokenGenerator(salt="test-salt"),
    )
    asyncio.get_event_loop_policy()
    return engine


async def _initialised(engine):
    await engine.initialise()
    return engine


@pytest.mark.asyncio
async def test_the_same_value_under_two_categories_gets_two_tokens(engine):
    # A word a domain label reclaims from PERSON must stop being labelled
    # PERSON. Before this, the first token minted was returned for ever.
    await _initialised(engine)

    as_person = await engine._store_span("ako", EntityType.PERSON, "scope-1")
    as_username = await engine._store_span("ako", EntityType.USERNAME, "scope-1")

    assert as_person != as_username
    assert as_person.startswith("{{PERSON:")
    assert as_username.startswith("{{USERNAME:")


@pytest.mark.asyncio
async def test_the_stored_record_carries_the_category_masked_under(engine):
    await _initialised(engine)

    await engine._store_span("ako", EntityType.PERSON, "scope-1")
    token = await engine._store_span("ako", EntityType.USERNAME, "scope-1")

    record = await engine._storage.get(token)
    assert record.entity_type == "USERNAME"


@pytest.mark.asyncio
async def test_repeating_a_value_in_one_category_still_deduplicates(engine):
    # The point of the value-hash index: one encrypted record per value, not
    # one per occurrence.
    await _initialised(engine)

    first = await engine._store_span("ako", EntityType.PERSON, "scope-1")
    await engine._store_span("ako", EntityType.USERNAME, "scope-1")
    again = await engine._store_span("ako", EntityType.PERSON, "scope-1")

    assert again == first


@pytest.mark.asyncio
async def test_both_categories_still_unmask_to_the_original_value(engine):
    await _initialised(engine)

    as_person = await engine._store_span("ako", EntityType.PERSON, "scope-1")
    as_username = await engine._store_span("ako", EntityType.USERNAME, "scope-1")

    assert await engine.unmask(as_person, scope="scope-1", actor="t") == "ako"
    assert await engine.unmask(as_username, scope="scope-1", actor="t") == "ako"


@pytest.mark.asyncio
async def test_scopes_stay_isolated(engine):
    await _initialised(engine)

    here = await engine._store_span("ako", EntityType.PERSON, "scope-1")
    there = await engine._store_span("ako", EntityType.PERSON, "scope-2")

    assert here != there
