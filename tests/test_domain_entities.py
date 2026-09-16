"""
tests.test_domain_entities
===========================
Coverage for the configurable domain-specific entity layer:
  - a category declared in config is detected, masked and unmasked exactly
    like a built-in one, including through the token round-trip;
  - ``context_words`` gates a loose pattern on nearby wording;
  - a rule naming an existing category adds a pattern to it;
  - config can come from a JSON file, from dicts, or from the
    ``PII_PROTECT_DOMAIN_ENTITIES`` environment variable;
  - malformed rules fail at load time with a message naming the problem.

Author: Neeraj Silavanuru
"""

import json

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.ner import NEREngine
from pii_protect.ner.domain import (
    CONFIG_ENV_VAR,
    DomainEntity,
    DomainEntityConfigError,
    DomainEntityLayer,
    load_domain_entities,
)
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import EntityType

FIXED_KEY = AESGCMCipher.generate_key()

CUSTOMER_REFERENCE = {
    "name": "CUSTOMER_REFERENCE",
    "pattern": r"\bCRN-\d{8}\b",
    "confidence": 0.95,
}

POLICY_NUMBER = {
    "name": "POLICY_NUMBER",
    "pattern": r"\bPOL\d{6}\b",
    "context_words": ["policy"],
    "context_window": 30,
}


def build_engine(entities):
    """A masking engine whose NER layer carries the given domain rules."""
    return PIIMaskingEngine(
        storage=InMemoryStorage(),
        ner_engine=NEREngine(domain_entities=entities),
        encryption_key=FIXED_KEY,
        token_generator=DeterministicTokenGenerator(
            salt=DeterministicTokenGenerator.generate_salt()
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Detection
# ─────────────────────────────────────────────────────────────────────────────


def test_declared_category_is_detected():
    layer = DomainEntityLayer(load_domain_entities([CUSTOMER_REFERENCE]))
    spans = layer.detect("Please quote CRN-45012398 when you call.")

    assert len(spans) == 1
    assert spans[0].text == "CRN-45012398"
    assert spans[0].entity_type == "CUSTOMER_REFERENCE"
    assert spans[0].entity_type.value == "CUSTOMER_REFERENCE"
    assert spans[0].source == "domain"


def test_declared_name_becomes_a_real_entity_type():
    DomainEntityLayer(load_domain_entities([CUSTOMER_REFERENCE]))

    # Every downstream path depends on these two working.
    assert EntityType("CUSTOMER_REFERENCE").value == "CUSTOMER_REFERENCE"
    assert EntityType.PERSON.value == "PERSON"


def test_context_words_gate_a_loose_pattern():
    layer = DomainEntityLayer(load_domain_entities([POLICY_NUMBER]))

    assert layer.detect("Renew policy POL123456 before May.")
    assert not layer.detect("Batch POL123456 shipped on Tuesday.")


def test_rule_naming_an_existing_category_extends_it():
    layer = DomainEntityLayer(
        load_domain_entities([{"name": "ACCOUNT", "pattern": r"\bACC/\d{6}\b"}])
    )
    spans = layer.detect("Transfer to ACC/889120 today.")

    assert len(spans) == 1
    assert spans[0].entity_type is EntityType.ACCOUNT


def test_non_matching_text_yields_nothing():
    layer = DomainEntityLayer(load_domain_entities([CUSTOMER_REFERENCE]))
    assert layer.detect("No identifiers in this sentence at all.") == []


# ─────────────────────────────────────────────────────────────────────────────
#  Through the masking engine
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_declared_category_masks_and_unmasks():
    text = "Please quote CRN-45012398 when you call."

    async with build_engine([CUSTOMER_REFERENCE]) as engine:
        result = await engine.mask(text)

        assert "CRN-45012398" not in result.masked_text
        assert "CUSTOMER_REFERENCE" in result.masked_text
        assert result.entity_counts["CUSTOMER_REFERENCE"] == 1

        assert await engine.unmask(result.masked_text) == text


@pytest.mark.asyncio
async def test_declared_category_can_be_ignored():
    text = "Please quote CRN-45012398 when you call."

    async with build_engine([CUSTOMER_REFERENCE]) as engine:
        result = await engine.mask(text, ignore_entities=["CUSTOMER_REFERENCE"])
        assert result.masked_text == text


@pytest.mark.asyncio
async def test_declared_category_redacts():
    async with build_engine([CUSTOMER_REFERENCE]) as engine:
        redacted = engine.redact("Please quote CRN-45012398 when you call.")

    assert "CRN-45012398" not in redacted
    assert "[REDACTED:CUSTOMER_REFERENCE]" in redacted


@pytest.mark.asyncio
async def test_built_in_categories_still_work_alongside():
    async with build_engine([CUSTOMER_REFERENCE]) as engine:
        result = await engine.mask("Mail ana@acme.com about CRN-45012398.")

    assert "ana@acme.com" not in result.masked_text
    assert result.entity_counts["EMAIL"] == 1
    assert result.entity_counts["CUSTOMER_REFERENCE"] == 1


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration sources
# ─────────────────────────────────────────────────────────────────────────────


def test_rules_load_from_a_json_file(tmp_path):
    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps([CUSTOMER_REFERENCE, POLICY_NUMBER]))

    entities = load_domain_entities(path)

    assert [entity.name for entity in entities] == [
        "CUSTOMER_REFERENCE",
        "POLICY_NUMBER",
    ]
    assert entities[0].confidence == 0.95
    assert entities[1].context_words == ("policy",)


def test_rules_load_from_the_environment(tmp_path, monkeypatch):
    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps([CUSTOMER_REFERENCE]))
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))

    spans = NEREngine().detect("Please quote CRN-45012398 when you call.")

    assert any(span.entity_type == "CUSTOMER_REFERENCE" for span in spans)


def test_ready_made_objects_pass_through():
    entity = DomainEntity(name="TICKET_ID", pattern=r"\bTKT-\d{5}\b")
    assert load_domain_entities([entity]) == [entity]


def test_no_configuration_means_no_layer(monkeypatch):
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    spans = NEREngine().detect("Please quote CRN-45012398 when you call.")
    assert not any(span.source == "domain" for span in spans)


# ─────────────────────────────────────────────────────────────────────────────
#  Malformed configuration
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rule,expected",
    [
        ({"name": "lower_case", "pattern": "x"}, "UPPER_SNAKE_CASE"),
        ({"name": "BAD_RE", "pattern": "([unclosed"}, "valid regular expression"),
        ({"name": "EMPTY", "pattern": "x*"}, "empty string"),
        ({"name": "TOO_SURE", "pattern": "x", "confidence": 2}, "between 0 and 1"),
        ({"pattern": "x"}, "missing 'name'"),
        ({"name": "NO_PATTERN"}, "missing 'pattern'"),
        ({"name": "TYPO", "pattern": "x", "confidenc": 0.9}, "unknown field"),
    ],
)
def test_malformed_rule_is_rejected(rule, expected):
    with pytest.raises(DomainEntityConfigError, match=expected):
        load_domain_entities([rule])


def test_duplicate_names_are_rejected():
    rule = {"name": "DUPLICATED", "pattern": r"\bA\d\b"}
    with pytest.raises(DomainEntityConfigError, match="more than once"):
        load_domain_entities([rule, rule])


def test_a_missing_config_file_names_the_path(tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(DomainEntityConfigError, match="nope.json"):
        load_domain_entities(missing)


def test_a_non_list_config_file_is_rejected(tmp_path):
    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps({"name": "NOT_A_LIST", "pattern": "x"}))

    with pytest.raises(DomainEntityConfigError, match="JSON list"):
        load_domain_entities(path)
