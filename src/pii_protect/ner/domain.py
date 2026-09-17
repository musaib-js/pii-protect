"""
pii_protect.ner.domain
=======================
Configurable domain-specific entity layer, detected by GLiNER.

Every category in :class:`~pii_protect.types.EntityType` is one the library
authors chose. A deployment always has its own: a bank's customer reference
number, an insurer's policy code, a telco's subscriber ID. Adding one used to
mean editing the enum and the regex library — a library change for what is
really a deployment detail.

This layer takes those categories from configuration instead, and finds them
the way GLiNER finds anything: zero-shot, from a natural-language label::

    from pii_protect import NEREngine

    engine = NEREngine(domain_entities="domain_entities.json")

where the file is a list of rules::

    [
      {
        "label": "customer reference number",
        "name": "CUSTOMER_REFERENCE",
        "context_words": ["customer reference", "crn"]
      }
    ]

``label`` is the only required field — it is the prompt handed to the model,
so it reads as a lowercase noun phrase, not as a code. ``name`` is the
``EntityType`` the matches land under, and defaults to the label upper-cased.

Set ``PII_PROTECT_DOMAIN_ENTITIES`` to that path and even the constructor
argument is unnecessary — an existing deployment picks the new categories up
with no code change at all.

A declared name becomes a real ``EntityType`` member, so it flows through
masking, token round-tripping, entity counts and partial-mask rules exactly
like a built-in category.

Categories can also be added for one call only, the mirror image of
``ignore_entities``::

    await engine.mask(text, detect_entities=["policy number"])

Author: Neeraj Silavanuru
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol, Sequence, Union

from pii_protect.exceptions import PIIShieldError
from pii_protect.types import DetectedSpan, EntityType

logger = logging.getLogger(__name__)

#: Environment variable holding a path to a domain entity config file. Read
#: when ``NEREngine`` is constructed without an explicit ``domain_entities``.
CONFIG_ENV_VAR = "PII_PROTECT_DOMAIN_ENTITIES"

#: Characters either side of a match to search when ``context_words`` is set.
DEFAULT_CONTEXT_WINDOW = 40

#: ``source`` recorded on spans from this layer, alongside 'regex', 'spacy',
#: 'gliner' and 'privacy_filter'.
SOURCE = "domain"

_VALID_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
_NAME_SEPARATORS = re.compile(r"[^A-Za-z0-9]+")


class DomainEntityConfigError(PIIShieldError):
    """A domain entity rule is malformed."""


class SupportsPredict(Protocol):
    """The slice of ``GLiNERLayer`` this layer needs.

    Declared as a protocol so the layer takes the model as a collaborator
    rather than importing it: ``ner.engine`` already imports this module.
    """

    def predict(
        self, text: str, labels: Sequence[str], threshold: Optional[float] = None
    ) -> list[dict]: ...


def entity_name_from_label(label: str) -> str:
    """``"customer reference number"`` to ``"CUSTOMER_REFERENCE_NUMBER"``."""
    name = _NAME_SEPARATORS.sub("_", label.strip()).strip("_").upper()
    if not _VALID_NAME.fullmatch(name):
        raise DomainEntityConfigError(
            f"Cannot derive an entity type name from label {label!r}. Give the "
            "rule an explicit 'name' in UPPER_SNAKE_CASE."
        )
    return name


@dataclass(frozen=True)
class DomainEntity:
    """One deployment-declared PII category and the label that finds it.

    Parameters
    ----------
    label : str
        The natural-language phrase handed to GLiNER, e.g. ``"customer
        reference number"``. Zero-shot detection reads this as English, so
        a descriptive lowercase noun phrase finds far more than a code.
    name : str
        The category, UPPER_SNAKE_CASE. Becomes an ``EntityType`` member and
        appears in tokens and entity counts under this name. Defaults to the
        label upper-cased. Naming an existing category (e.g. ``ACCOUNT``)
        routes matches to it rather than creating a new one.
    threshold : Optional[float]
        Minimum model score for this label, overriding the GLiNER layer's
        own threshold. Lower it for a label the model is hesitant about.
    context_words : tuple[str, ...]
        If given, a match only counts when one of these words appears within
        ``context_window`` characters — the way to gate a label that is
        broad enough to fire on ordinary prose.
    context_window : int
        How far either side of the match to look for ``context_words``.
    """

    label: str
    name: str = ""
    threshold: Optional[float] = None
    context_words: tuple[str, ...] = ()
    context_window: int = DEFAULT_CONTEXT_WINDOW

    context_re: Optional[re.Pattern] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.label.strip():
            raise DomainEntityConfigError(
                "Domain entity 'label' must not be empty — it is the phrase "
                "GLiNER is asked to find (e.g. 'customer reference number')."
            )

        name = self.name or entity_name_from_label(self.label)
        if not _VALID_NAME.fullmatch(name):
            raise DomainEntityConfigError(
                f"Domain entity name {name!r} must be UPPER_SNAKE_CASE, "
                "starting with a letter (e.g. 'CUSTOMER_REFERENCE')."
            )
        object.__setattr__(self, "name", name)

        if self.threshold is not None and not 0.0 <= self.threshold <= 1.0:
            raise DomainEntityConfigError(
                f"{name}: threshold must be between 0 and 1, got {self.threshold}."
            )

        if self.context_window < 0:
            raise DomainEntityConfigError(
                f"{name}: context_window must not be negative."
            )

        object.__setattr__(self, "context_re", _build_context_re(self.context_words))


def _build_context_re(context_words: Sequence[str]) -> Optional[re.Pattern]:
    """One case-insensitive alternation of the words, or None if there are none."""
    words = [word.strip() for word in context_words if word.strip()]
    if not words:
        return None
    return re.compile("|".join(re.escape(word) for word in words), re.IGNORECASE)


def register_entity_type(name: str) -> EntityType:
    """Return the ``EntityType`` for ``name``, adding it to the enum if new.

    ``EntityType`` is a closed ``str`` enum, and the masking, token and
    storage paths all rely on that: they read ``entity_type.value`` and, when
    parsing a token back out of masked text, call ``EntityType(label)``. A
    configured category therefore cannot be a plain string — it has to be a
    real member, or unmasking a value in that category raises ``ValueError``.

    Adding one after class creation is the only way to keep those paths
    untouched, so that is what this does.
    """
    existing = EntityType._member_map_.get(name)
    if existing is not None:
        return existing  # type: ignore[return-value]

    member = str.__new__(EntityType, name)
    member._name_ = name
    member._value_ = name
    EntityType._member_map_[name] = member
    EntityType._value2member_map_[name] = member
    EntityType._member_names_.append(name)

    # The lines above reach into enum internals, which are not a documented
    # API. Prove the member really is usable rather than discovering at
    # unmask time, in production, that a Python upgrade changed them.
    if EntityType(name) is not member or member.value != name:
        raise DomainEntityConfigError(
            f"Could not register domain entity type {name!r} on this Python "
            f"({sys.version.split()[0]}). Please report this — the enum "
            "internals pii_protect relies on have changed."
        )

    logger.info("Registered domain entity type %s", name)
    return member


def load_domain_entities(
    source: Union[str, Path, Iterable[Any]],
) -> list[DomainEntity]:
    """Build rules from a JSON file path, or from already-parsed dicts.

    Accepts a path to a JSON file holding a list of rule objects, or any
    iterable of rule dicts, ready-made :class:`DomainEntity` objects or bare
    label strings — so a caller reading its own YAML or database config can
    pass the dicts straight in without writing them back out to a file.
    """
    if isinstance(source, (str, Path)):
        raw = _read_config_file(Path(source))
    else:
        raw = list(source)

    entities = [_to_entity(item, index) for index, item in enumerate(raw)]

    seen: set[str] = set()
    for entity in entities:
        if entity.label.lower() in seen:
            raise DomainEntityConfigError(
                f"Domain entity label {entity.label!r} is declared more than "
                "once. Give each rule its own label."
            )
        seen.add(entity.label.lower())

    return entities


def _read_config_file(path: Path) -> list[Any]:
    """Read and parse the config file, failing with the path in the message."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise DomainEntityConfigError(
            f"Could not read domain entity config {path} — {error}"
        ) from error

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise DomainEntityConfigError(
            f"{path} is not valid JSON — {error}"
        ) from error

    if not isinstance(parsed, list):
        raise DomainEntityConfigError(
            f"{path} must hold a JSON list of entity rules, "
            f"got {type(parsed).__name__}."
        )

    return parsed


def _to_entity(item: Any, index: int) -> DomainEntity:
    """One config entry to a rule, naming the position when it is malformed."""
    if isinstance(item, DomainEntity):
        return item

    if isinstance(item, str):
        return DomainEntity(label=item)

    if not isinstance(item, dict):
        raise DomainEntityConfigError(
            f"Entity rule at position {index} must be an object or a label "
            f"string, got {type(item).__name__}."
        )

    known = {"label", "name", "threshold", "context_words", "context_window"}
    unknown = set(item) - known
    if unknown:
        raise DomainEntityConfigError(
            f"Entity rule at position {index} has unknown field(s): "
            f"{', '.join(sorted(unknown))}. Allowed: {', '.join(sorted(known))}."
        )

    if "label" not in item:
        raise DomainEntityConfigError(
            f"Entity rule at position {index} is missing 'label' — the phrase "
            "GLiNER is asked to find, e.g. 'customer reference number'."
        )

    threshold = item.get("threshold")
    return DomainEntity(
        label=str(item["label"]),
        name=str(item.get("name", "")),
        threshold=None if threshold is None else float(threshold),
        context_words=tuple(item.get("context_words", ())),
        context_window=int(item.get("context_window", DEFAULT_CONTEXT_WINDOW)),
    )


def domain_entities_from_env() -> list[DomainEntity]:
    """Rules from the path in ``PII_PROTECT_DOMAIN_ENTITIES``, or none."""
    path = os.environ.get(CONFIG_ENV_VAR, "").strip()
    if not path:
        return []
    return load_domain_entities(path)


class DomainEntityLayer:
    """Detection layer for deployment-declared entity categories.

    Runs the configured labels through the GLiNER model the engine already
    loaded, in a prediction of their own — so a deployment's categories are
    detected the same zero-shot way as the built-in ones, without the
    library's own label list growing a deployment's vocabulary.
    """

    def __init__(
        self, entities: Sequence[DomainEntity], gliner: SupportsPredict
    ) -> None:
        self._gliner = gliner
        self._entities = tuple(entities)
        self._types = {
            entity.name: register_entity_type(entity.name) for entity in self._entities
        }
        logger.info(
            "DomainEntityLayer ready (%d rule(s): %s)",
            len(self._entities),
            ", ".join(entity.label for entity in self._entities) or "none",
        )

    @property
    def entities(self) -> tuple[DomainEntity, ...]:
        """The configured rules, in declaration order."""
        return self._entities

    def detect(
        self, text: str, extra_entities: Sequence[DomainEntity] = ()
    ) -> list[DetectedSpan]:
        """Run the configured labels — plus any for this call only — on the text."""
        rules = self._entities + tuple(extra_entities)
        if not rules:
            return []

        by_label = {rule.label.lower(): rule for rule in rules}
        types = dict(self._types)
        for rule in extra_entities:
            types.setdefault(rule.name, register_entity_type(rule.name))

        # One prediction per distinct threshold: the model takes a single
        # threshold per call, and most deployments use one for everything.
        spans: list[DetectedSpan] = []
        thresholds: dict[Optional[float], list[str]] = {}
        for rule in rules:
            thresholds.setdefault(rule.threshold, []).append(rule.label)

        for threshold, labels in thresholds.items():
            for entity in self._gliner.predict(text, labels, threshold):
                rule = by_label.get(str(entity["label"]).lower())
                if rule is None:
                    continue

                value = entity["text"]
                if not value:
                    continue

                if rule.context_re is not None and not self._has_context(
                    text, entity["start"], entity["end"], rule
                ):
                    continue

                spans.append(
                    DetectedSpan(
                        start=entity["start"],
                        end=entity["end"],
                        text=value,
                        entity_type=types[rule.name],
                        confidence=float(entity["score"]),
                        source=SOURCE,
                    )
                )

        spans.sort(key=lambda span: span.start)
        return spans

    def _has_context(
        self, text: str, start: int, end: int, entity: DomainEntity
    ) -> bool:
        """True if one of the rule's context words sits near the match."""
        window_start = max(0, start - entity.context_window)
        window_end = min(len(text), end + entity.context_window)
        return bool(entity.context_re.search(text[window_start:window_end]))
