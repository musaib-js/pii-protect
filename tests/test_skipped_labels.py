"""
tests.test_skipped_labels
==========================
Labels asked about only so their answers can be thrown away.

Naming one gives the model somewhere truer to put a span, which is what makes
it stop assigning that span to the category it was getting wrong — "job title"
is why "the accountant said..." is not a PERSON. A deployment names its own
the same way, and that is how a false positive is dealt with without a code
change.

The model is stubbed: this is about which labels are asked for and which
answers are kept, not about the weights.
"""

import pytest

from pii_protect.ner.engine import (
    SKIP_LABELS_ENV_VAR,
    GLiNERLayer,
    skip_labels_from_env,
)
from pii_protect.types import EntityType


def _layer(skip_labels=None) -> GLiNERLayer:
    """A GLiNERLayer with its model and loading bypassed."""
    layer = GLiNERLayer.__new__(GLiNERLayer)
    layer._threshold = 0.5
    layer._max_chars = 4000
    extra = tuple(
        label.strip().lower() for label in (skip_labels or ()) if label.strip()
    )
    layer._skipped = frozenset(GLiNERLayer.DEFAULT_SKIP_LABELS) | frozenset(extra)
    layer._labels = (
        *GLiNERLayer.DEFAULT_LABELS,
        *(l for l in extra if l not in GLiNERLayer.DEFAULT_LABELS),
    )
    return layer


FOUND = [
    {"label": "person", "text": "Juan Cruz", "start": 0, "end": 9, "score": 0.9},
    {"label": "job title", "text": "Senior Manager", "start": 14, "end": 28, "score": 0.9},
    {"label": "real estate", "text": "property", "start": 32, "end": 40, "score": 0.9},
]


def _detect(layer, found=FOUND):
    layer.predict = lambda text, labels, threshold=None: found  # noqa: ARG005
    return layer.detect("Juan Cruz is Senior Manager, property")


def test_the_built_in_labels_are_asked_about_and_discarded():
    assert "job title" in _layer()._labels
    assert "job title" in _layer()._skipped
    # "real estate" is not declared here, so it survives as OTHER.
    assert [s.entity_type for s in _detect(_layer())] == [
        EntityType.PERSON,
        EntityType.OTHER,
    ]


def test_a_declared_label_is_asked_about_in_the_same_prediction():
    # Asking in a call of its own would let the model go on assigning the span
    # to whatever it was getting wrong — competing is the point.
    layer = _layer(skip_labels=["real estate"])

    assert "real estate" in layer._labels
    assert layer._labels[: len(GLiNERLayer.DEFAULT_LABELS)] == GLiNERLayer.DEFAULT_LABELS


def test_a_declared_label_is_discarded_with_the_built_in_ones():
    kept = [s.entity_type for s in _detect(_layer(skip_labels=["real estate"]))]

    assert kept == [EntityType.PERSON]


def test_a_deployments_labels_are_added_not_substituted():
    # Declaring one must not quietly un-discard job titles, or fixing one
    # false positive starts masking every job title in every message.
    layer = _layer(skip_labels=["real estate"])

    assert {"job title", "age group", "real estate"} == layer._skipped


def test_label_order_is_preserved():
    # The label list is part of the prompt: moving "job title" changed whether
    # "Engineer Santos" was masked whole.
    layer = _layer(skip_labels=["real estate"])

    assert layer._labels[0] == "job title"
    assert layer._labels[-1] == "real estate"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("real estate", ("real estate",)),
        ("real estate, vehicle colour ,", ("real estate", "vehicle colour")),
        ("", ()),
    ],
)
def test_labels_come_from_the_environment(monkeypatch, value, expected):
    monkeypatch.setenv(SKIP_LABELS_ENV_VAR, value)

    assert skip_labels_from_env() == expected


def test_no_variable_means_no_extra_labels(monkeypatch):
    monkeypatch.delenv(SKIP_LABELS_ENV_VAR, raising=False)

    assert skip_labels_from_env() == ()
