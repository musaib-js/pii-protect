"""
tests.test_domain_entities
===========================
Coverage for the configurable domain-specific entity layer, now that it
detects through GLiNER rather than through regex patterns:
  - a category declared in config is detected, masked and unmasked exactly
    like a built-in one, including through the token round-trip;
  - the configured labels — and only those — are what the model is asked for;
  - ``context_words`` gates a label on nearby wording;
  - a per-rule ``threshold`` overrides the layer's own;
  - ``detect_entities`` adds categories for one call, mirroring
    ``ignore_entities``;
  - config can come from a JSON file, from dicts, from bare label strings,
    or from the ``PII_PROTECT_DOMAIN_ENTITIES`` environment variable;
  - malformed rules fail at load time with a message naming the problem.

The model itself is stubbed: these tests are about the layer's contract with
GLiNER (labels in, spans out), not about the weights, which would otherwise
have to be downloaded to run the suite.

Author: Neeraj Silavanuru
"""

import json

import pytest

from pii_protect import PIIMaskingEngine
from pii_protect.crypto import AESGCMCipher
from pii_protect.ner.domain import (
    CONFIG_ENV_VAR,
    DomainEntity,
    DomainEntityConfigError,
    DomainEntityLayer,
    entity_name_from_label,
    load_domain_entities,
)
from pii_protect.storage import InMemoryStorage
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import EntityType

FIXED_KEY = AESGCMCipher.generate_key()

CUSTOMER_REFERENCE = {
    "label": "customer reference number",
    "name": "CUSTOMER_REFERENCE",
}

POLICY_NUMBER = {
    "label": "policy number",
    "context_words": ["policy"],
    "context_window": 30,
}


class FakeGLiNER:
    """Stands in for ``GLiNERLayer``, returning scripted spans.

    ``found`` maps a label to the substrings the "model" finds for it. Every
    call's labels and threshold are recorded, because *which* labels the
    layer asks for is half of what this feature does.
    """

    def __init__(self, found=None, score=0.90):
        self.found = found or {}
        self.score = score
        self.calls = []

    def predict(self, text, labels, threshold=None):
        self.calls.append((tuple(labels), threshold))
        entities = []
        for label in labels:
            for value in self.found.get(label, ()):
                start = text.find(value)
                if start == -1:
                    continue
                entities.append(
                    {
                        "label": label,
                        "text": value,
                        "start": start,
                        "end": start + len(value),
                        "score": self.score,
                    }
                )
        return entities

    @property
    def requested_labels(self):
        """Every label asked for across all calls."""
        return {label for labels, _ in self.calls for label in labels}


class FakeNER:
    """A whole NER engine stubbed down to the domain layer, for mask tests."""

    def __init__(self, entities, found):
        self._layer = DomainEntityLayer(
            load_domain_entities(entities), FakeGLiNER(found)
        )

    def detect(self, text, detect_entities=None):
        extra = load_domain_entities(detect_entities) if detect_entities else []
        return self._layer.detect(text, extra)


def build_engine(entities, found):
    """A masking engine whose detection is the stubbed domain layer."""
    return PIIMaskingEngine(
        storage=InMemoryStorage(),
        ner_engine=FakeNER(entities, found),
        encryption_key=FIXED_KEY,
        token_generator=DeterministicTokenGenerator(
            salt=DeterministicTokenGenerator.generate_salt()
        ),
    )


def build_layer(entities, found, score=0.90):
    model = FakeGLiNER(found, score)
    return DomainEntityLayer(load_domain_entities(entities), model), model


# ─────────────────────────────────────────────────────────────────────────────
#  Detection
# ─────────────────────────────────────────────────────────────────────────────


def test_declared_category_is_detected():
    layer, _ = build_layer(
        [CUSTOMER_REFERENCE], {"customer reference number": ["CRN-48210033"]}
    )

    spans = layer.detect("Please quote CRN-48210033 on any correspondence.")

    assert len(spans) == 1
    assert spans[0].text == "CRN-48210033"
    assert spans[0].entity_type.value == "CUSTOMER_REFERENCE"
    assert spans[0].source == "domain"
    assert spans[0].confidence == pytest.approx(0.90)


def test_the_model_is_asked_for_the_configured_labels():
    layer, model = build_layer([CUSTOMER_REFERENCE, POLICY_NUMBER], {})

    layer.detect("nothing of interest here")

    assert model.requested_labels == {"customer reference number", "policy number"}


def test_spans_carry_the_offsets_of_the_original_text():
    text = "Ref: CRN-48210033 filed."
    layer, _ = build_layer(
        [CUSTOMER_REFERENCE], {"customer reference number": ["CRN-48210033"]}
    )

    span = layer.detect(text)[0]

    assert text[span.start : span.end] == "CRN-48210033"


def test_name_defaults_to_the_label_upper_cased():
    layer, _ = build_layer(["policy number"], {"policy number": ["POL778312"]})

    assert layer.detect("policy POL778312")[0].entity_type.value == "POLICY_NUMBER"


def test_declared_name_becomes_a_real_entity_type():
    build_layer([CUSTOMER_REFERENCE], {})

    assert EntityType("CUSTOMER_REFERENCE").value == "CUSTOMER_REFERENCE"


def test_context_words_gate_a_loose_label():
    found = {"policy number": ["778312"]}
    layer, _ = build_layer([POLICY_NUMBER], found)

    assert layer.detect("Your policy 778312 renews in May.")
    assert not layer.detect("Order 778312 shipped on Tuesday.")


def test_a_rule_naming_an_existing_category_routes_to_it():
    layer, _ = build_layer(
        [{"label": "internal account code", "name": "ACCOUNT"}],
        {"internal account code": ["ACC/884120"]},
    )

    assert layer.detect("Charged to ACC/884120.")[0].entity_type is EntityType.ACCOUNT


def test_a_per_rule_threshold_is_passed_to_the_model():
    layer, model = build_layer(
        [
            {"label": "policy number", "threshold": 0.3},
            {"label": "claim number", "threshold": 0.3},
            CUSTOMER_REFERENCE,
        ],
        {},
    )

    layer.detect("some text")

    by_threshold = {threshold: labels for labels, threshold in model.calls}
    assert set(by_threshold[0.3]) == {"policy number", "claim number"}
    assert by_threshold[None] == ("customer reference number",)


def test_non_matching_text_yields_nothing():
    layer, _ = build_layer([CUSTOMER_REFERENCE], {})

    assert layer.detect("Nothing sensitive in this sentence.") == []


def test_no_rules_means_the_model_is_not_called():
    layer, model = build_layer([], {})

    assert layer.detect("Some text.") == []
    assert model.calls == []


# ─────────────────────────────────────────────────────────────────────────────
#  Per-call categories (the mirror of ignore_entities)
# ─────────────────────────────────────────────────────────────────────────────


def test_detect_entities_adds_a_category_for_one_call():
    layer, _ = build_layer([], {"policy number": ["POL778312"]})
    extra = load_domain_entities(["policy number"])

    assert layer.detect("policy POL778312") == []

    spans = layer.detect("policy POL778312", extra)
    assert len(spans) == 1
    assert spans[0].entity_type.value == "POLICY_NUMBER"


@pytest.mark.asyncio
async def test_detect_entities_masks_through_the_engine():
    engine = build_engine([], {"policy number": ["POL778312"]})
    await engine.initialise()

    text = "Policy POL778312 is active."
    result = await engine.mask(text, detect_entities=["policy number"])

    assert "POL778312" not in result.masked_text
    assert result.entity_counts == {"POLICY_NUMBER": 1}
    assert await engine.unmask(result.masked_text) == text


@pytest.mark.asyncio
async def test_without_detect_entities_the_same_text_is_untouched():
    engine = build_engine([], {"policy number": ["POL778312"]})
    await engine.initialise()

    result = await engine.mask("Policy POL778312 is active.")

    assert result.masked_text == "Policy POL778312 is active."
    assert result.token_count == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Through the masking engine
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_declared_category_masks_and_unmasks():
    engine = build_engine(
        [CUSTOMER_REFERENCE], {"customer reference number": ["CRN-48210033"]}
    )
    await engine.initialise()

    text = "Please quote CRN-48210033 on any correspondence."
    result = await engine.mask(text)

    assert "CRN-48210033" not in result.masked_text
    assert result.entity_counts == {"CUSTOMER_REFERENCE": 1}
    assert await engine.unmask(result.masked_text) == text


@pytest.mark.asyncio
async def test_declared_category_can_be_ignored():
    engine = build_engine(
        [CUSTOMER_REFERENCE], {"customer reference number": ["CRN-48210033"]}
    )
    await engine.initialise()

    result = await engine.mask(
        "Quote CRN-48210033 please.", ignore_entities=["CUSTOMER_REFERENCE"]
    )

    assert "CRN-48210033" in result.masked_text
    assert result.token_count == 0


@pytest.mark.asyncio
async def test_declared_category_redacts():
    engine = build_engine(
        [CUSTOMER_REFERENCE], {"customer reference number": ["CRN-48210033"]}
    )

    assert engine.redact("Quote CRN-48210033.") == (
        "Quote [REDACTED:CUSTOMER_REFERENCE]."
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration loading
# ─────────────────────────────────────────────────────────────────────────────


def test_rules_load_from_a_json_file(tmp_path):
    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps([CUSTOMER_REFERENCE, POLICY_NUMBER]))

    entities = load_domain_entities(path)

    assert [entity.label for entity in entities] == [
        "customer reference number",
        "policy number",
    ]


def test_rules_load_from_the_environment(tmp_path, monkeypatch):
    from pii_protect.ner.domain import domain_entities_from_env

    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps([CUSTOMER_REFERENCE]))
    monkeypatch.setenv(CONFIG_ENV_VAR, str(path))

    assert [e.name for e in domain_entities_from_env()] == ["CUSTOMER_REFERENCE"]


def test_no_configuration_means_no_rules(monkeypatch):
    from pii_protect.ner.domain import domain_entities_from_env

    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)

    assert domain_entities_from_env() == []


def test_a_bare_label_string_is_a_rule():
    (entity,) = load_domain_entities(["policy number"])

    assert entity.label == "policy number"
    assert entity.name == "POLICY_NUMBER"


def test_ready_made_objects_pass_through():
    entity = DomainEntity(label="ticket id", name="TICKET_ID")

    assert load_domain_entities([entity]) == [entity]


def test_entity_name_from_label():
    assert entity_name_from_label("customer reference number") == (
        "CUSTOMER_REFERENCE_NUMBER"
    )
    assert entity_name_from_label("  policy-number ") == "POLICY_NUMBER"


@pytest.mark.parametrize(
    "rule,expected",
    [
        ({"label": "x", "name": "lower_case"}, "UPPER_SNAKE_CASE"),
        ({"label": ""}, "must not be empty"),
        ({"label": "123"}, "Cannot derive an entity type name"),
        ({"label": "x", "threshold": 2}, "between 0 and 1"),
        ({"name": "NO_LABEL"}, "missing 'label'"),
        ({"label": "x", "labl": "typo"}, "unknown field"),
        ({"label": "x", "pattern": "y"}, "unknown field"),
    ],
)
def test_malformed_rule_is_rejected(rule, expected):
    with pytest.raises(DomainEntityConfigError, match=expected):
        load_domain_entities([rule])


def test_duplicate_labels_are_rejected():
    with pytest.raises(DomainEntityConfigError, match="more than once"):
        load_domain_entities(["policy number", "Policy Number"])


def test_a_missing_config_file_names_the_path(tmp_path):
    with pytest.raises(DomainEntityConfigError, match="nope.json"):
        load_domain_entities(tmp_path / "nope.json")


def test_a_non_list_config_file_is_rejected(tmp_path):
    path = tmp_path / "domain_entities.json"
    path.write_text(json.dumps({"label": "not a list"}))

    with pytest.raises(DomainEntityConfigError, match="JSON list"):
        load_domain_entities(path)
