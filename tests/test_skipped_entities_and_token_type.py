"""
tests.test_skipped_entities_and_token_type
===========================================
Two fixes that only show up once a deployment starts configuring categories:

  - which of GLiNER's own categories are discarded is a deployment's choice,
    not a constant. Naming a category is how a recurring false positive is
    dealt with: give the model a truer label for what it keeps mislabelling,
    then throw that label's answers away;

  - a value masked under one category and later detected as another gets a
    token for the category it was actually detected as. Deduplication matches
    on the value alone, so without this the first token ever minted is handed
    back for every later detection, still wearing the first category's label.

The model is stubbed — this is about the layer's contract, not the weights.
"""

import asyncio

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.ner.engine import GLiNERLayer, _normalise_entity_names
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import DetectedSpan, EntityType

FIXED_KEY = AESGCMCipher.generate_key()


def _layer(skip_entities=None) -> GLiNERLayer:
    """A GLiNERLayer with its model and loading bypassed."""
    layer = GLiNERLayer.__new__(GLiNERLayer)
    layer._labels = GLiNERLayer.DEFAULT_LABELS
    layer._threshold = 0.5
    layer._max_chars = 4000
    layer._skipped = _normalise_entity_names(
        GLiNERLayer.DEFAULT_SKIPPED_ENTITIES if skip_entities is None else skip_entities
    )
    return layer


def _predicting(layer: GLiNERLayer, entities):
    layer.predict = lambda text, labels, threshold=None: entities  # noqa: ARG005
    return layer


FOUND = [
    {"label": "person", "text": "Juan Cruz", "start": 0, "end": 9, "score": 0.9},
    {"label": "job title", "text": "Senior Manager", "start": 14, "end": 28, "score": 0.9},
]
TEXT = "Juan Cruz is Senior Manager"


# ─────────────────────────────────────────────────────────────────────────────
#  Skipping is configurable
# ─────────────────────────────────────────────────────────────────────────────


def test_job_titles_and_age_groups_are_discarded_by_default():
    # Both are asked for so the model does not file them under something that
    # is masked, but neither is private on its own.
    spans = _predicting(_layer(), FOUND).detect(TEXT)

    assert [span.entity_type for span in spans] == [EntityType.PERSON]


def test_a_deployment_can_choose_what_is_discarded():
    spans = _predicting(_layer(skip_entities=["PERSON"]), FOUND).detect(TEXT)

    # PERSON gone, and JOB_TITLE now kept — the default is replaced, not added to.
    assert [span.entity_type for span in spans] == [EntityType.JOB_TITLE]


def test_skipping_nothing_keeps_every_category():
    spans = _predicting(_layer(skip_entities=[]), FOUND).detect(TEXT)

    assert [span.entity_type for span in spans] == [
        EntityType.PERSON,
        EntityType.JOB_TITLE,
    ]


def test_entity_types_are_accepted_as_members_or_strings():
    from_members = _layer(skip_entities=[EntityType.PERSON, EntityType.JOB_TITLE])
    from_strings = _layer(skip_entities=["person", "JOB_TITLE"])

    assert from_members._skipped == from_strings._skipped


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
