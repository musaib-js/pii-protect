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
from pii_protect.ner.domain import SOURCE as DOMAIN_SOURCE
from pii_protect.ner.engine import (
    DEFAULT_SKIPPED_ENTITIES,
    SKIP_ENV_VAR,
    NEREngine,
    RegexNERLayer,
    SpanConflictResolver,
    TokenizerSafeSpanMerger,
    _normalise_entity_names,
    skip_entities_from_env,
)
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import DetectedSpan, EntityType

FIXED_KEY = AESGCMCipher.generate_key()


def _engine(skip_entities=None) -> NEREngine:
    """An NEREngine with only its regex layer, so no model has to load."""
    engine = NEREngine.__new__(NEREngine)
    engine._regex_layer = RegexNERLayer()
    engine._gliner_layer = None
    engine._spacy_layer = None
    engine._privacy_filter_layer = None
    engine._domain_layer = None
    engine._merger = TokenizerSafeSpanMerger()
    engine._resolver = SpanConflictResolver()
    engine._skipped = _normalise_entity_names(
        DEFAULT_SKIPPED_ENTITIES if skip_entities is None else skip_entities
    )
    return engine


TEXT = "write to juan@example.com or call 09171234567"


def test_a_declared_category_is_detected_unless_it_is_skipped():
    kept = [span.entity_type for span in _engine().detect(TEXT)]

    assert EntityType.EMAIL in kept
    assert EntityType.PHONE in kept


def test_a_skipped_category_comes_back_unmasked():
    # The whole point: detected, then dropped, so the text it covers is left
    # in the clear rather than replaced by a token.
    kept = [span.entity_type for span in _engine(skip_entities=["EMAIL"]).detect(TEXT)]

    assert EntityType.EMAIL not in kept
    assert EntityType.PHONE in kept


def test_skipping_nothing_keeps_every_category():
    kept = [span.entity_type for span in _engine(skip_entities=[]).detect(TEXT)]

    assert EntityType.EMAIL in kept
    assert EntityType.PHONE in kept


def test_entity_types_are_accepted_as_members_or_strings():
    from_members = _engine(skip_entities=[EntityType.EMAIL])
    from_strings = _engine(skip_entities=["email"])

    assert from_members._skipped == from_strings._skipped


def test_skipping_happens_after_conflict_resolution():
    # A skipped span still competes for its characters first. That is what
    # lets a declared decoy take a span away from a built-in category before
    # being dropped — filtering earlier would leave the original detection.
    resolver = SpanConflictResolver()
    generic = DetectedSpan(0, 8, "property", EntityType.ADDRESS, 0.64, "gliner")
    declared = DetectedSpan(0, 8, "property", EntityType.OTHER, 0.51, DOMAIN_SOURCE)

    winner = resolver.resolve([generic, declared])

    assert [span.entity_type for span in winner] == [EntityType.OTHER]


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


# ─────────────────────────────────────────────────────────────────────────────
#  The skip list from the environment
# ─────────────────────────────────────────────────────────────────────────────


def test_the_environment_sets_what_is_skipped(monkeypatch):
    monkeypatch.setenv(SKIP_ENV_VAR, "PROPERTY, JOB_TITLE ,")

    assert skip_entities_from_env() == frozenset({"PROPERTY", "JOB_TITLE"})


def test_an_unset_variable_leaves_the_default_in_place(monkeypatch):
    monkeypatch.delenv(SKIP_ENV_VAR, raising=False)

    assert skip_entities_from_env() is None


def test_an_empty_variable_means_discard_nothing(monkeypatch):
    # Different from unset: a deployment saying so explicitly.
    monkeypatch.setenv(SKIP_ENV_VAR, "")

    assert skip_entities_from_env() == frozenset()


def test_an_explicit_argument_wins_over_the_environment(monkeypatch):
    monkeypatch.setenv(SKIP_ENV_VAR, "EMAIL")

    assert _engine(skip_entities=["PHONE"])._skipped == frozenset({"PHONE"})


def test_the_environment_is_used_when_no_argument_is_given(monkeypatch):
    # Both halves have to be settable without code, or declaring a category
    # from config and then having to write code to skip it only renames the
    # false positive.
    monkeypatch.setenv(SKIP_ENV_VAR, "EMAIL")
    engine = NEREngine.__new__(NEREngine)
    engine._regex_layer = RegexNERLayer()
    engine._gliner_layer = engine._spacy_layer = None
    engine._privacy_filter_layer = engine._domain_layer = None
    engine._merger, engine._resolver = TokenizerSafeSpanMerger(), SpanConflictResolver()
    from_env = skip_entities_from_env()
    engine._skipped = from_env if from_env is not None else frozenset()

    kept = [span.entity_type for span in engine.detect(TEXT)]
    assert EntityType.EMAIL not in kept
    assert EntityType.PHONE in kept
