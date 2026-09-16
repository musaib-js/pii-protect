"""
pii_protect.ner.domain
=======================
Configurable domain-specific entity layer.

Every category in :class:`~pii_protect.types.EntityType` is one the library
authors chose. A deployment always has its own: a bank's customer reference
number, an insurer's policy code, a telco's subscriber ID. Adding one used to
mean editing the enum and the regex library — a library change for what is
really a deployment detail.

This layer takes those categories from configuration instead:

    from pii_protect import NEREngine

    engine = NEREngine(domain_entities="domain_entities.json")

where the file is a list of rules::

    [
      {
        "name": "CUSTOMER_REFERENCE",
        "pattern": "\\\\bCRN-\\\\d{8}\\\\b",
        "confidence": 0.95,
        "context_words": ["customer reference", "crn"]
      }
    ]

Set ``PII_PROTECT_DOMAIN_ENTITIES`` to that path and even the constructor
argument is unnecessary — an existing deployment picks the new categories up
with no code change at all.

A declared name becomes a real ``EntityType`` member, so it flows through
masking, token round-tripping, entity counts and partial-mask rules exactly
like a built-in category.

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
from typing import Any, Iterable, Optional, Sequence, Union

from pii_protect.exceptions import PIIShieldError
from pii_protect.types import DetectedSpan, EntityType

logger = logging.getLogger(__name__)

#: Environment variable holding a path to a domain entity config file. Read
#: when ``NEREngine`` is constructed without an explicit ``domain_entities``.
CONFIG_ENV_VAR = "PII_PROTECT_DOMAIN_ENTITIES"

#: Characters either side of a match to search when ``context_words`` is set.
DEFAULT_CONTEXT_WINDOW = 40

#: Default confidence for a declared rule. High, because an explicitly
#: configured pattern is a deliberate statement about this deployment's data,
#: not a general-purpose guess.
DEFAULT_CONFIDENCE = 0.90

#: ``source`` recorded on spans from this layer, alongside 'regex', 'spacy',
#: 'gliner' and 'privacy_filter'.
SOURCE = "domain"

_VALID_NAME = re.compile(r"[A-Z][A-Z0-9_]*")


class DomainEntityConfigError(PIIShieldError):
    """A domain entity rule is malformed."""


@dataclass(frozen=True)
class DomainEntity:
    """One deployment-declared PII category and the pattern that finds it.

    Parameters
    ----------
    name : str
        The category, UPPER_SNAKE_CASE. Becomes an ``EntityType`` member and
        appears in tokens and entity counts under this name. Naming an
        existing category (e.g. ``ACCOUNT``) adds a pattern to it rather than
        creating a new one.
    pattern : str
        Regular expression. Use ``\\b`` anchors — an unanchored pattern will
        match inside longer words. Inline flags such as ``(?i)`` are honoured.
    confidence : float
        0 to 1. Used to settle overlaps with other layers' spans.
    context_words : tuple[str, ...]
        If given, a match only counts when one of these words appears within
        ``context_window`` characters. The way to make a loose shape safe:
        ``\\d{8}`` alone matches any 8-digit number, but ``\\d{8}`` near the
        word "customer reference" is almost certainly the thing you mean.
    context_window : int
        How far either side of the match to look for ``context_words``.
    """

    name: str
    pattern: str
    confidence: float = DEFAULT_CONFIDENCE
    context_words: tuple[str, ...] = ()
    context_window: int = DEFAULT_CONTEXT_WINDOW

    compiled: re.Pattern = field(init=False, repr=False, compare=False)
    context_re: Optional[re.Pattern] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not _VALID_NAME.fullmatch(self.name):
            raise DomainEntityConfigError(
                f"Domain entity name {self.name!r} must be UPPER_SNAKE_CASE, "
                "starting with a letter (e.g. 'CUSTOMER_REFERENCE')."
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise DomainEntityConfigError(
                f"{self.name}: confidence must be between 0 and 1, "
                f"got {self.confidence}."
            )

        if self.context_window < 0:
            raise DomainEntityConfigError(
                f"{self.name}: context_window must not be negative."
            )

        try:
            compiled = re.compile(self.pattern)
        except re.error as error:
            raise DomainEntityConfigError(
                f"{self.name}: pattern is not a valid regular expression — {error}"
            ) from error

        if compiled.match(""):
            raise DomainEntityConfigError(
                f"{self.name}: pattern matches the empty string, which would "
                "flag every position in the text."
            )

        object.__setattr__(self, "compiled", compiled)
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
    iterable of rule dicts or ready-made :class:`DomainEntity` objects — so a
    caller reading its own YAML or database config can pass the dicts straight
    in without writing them back out to a file.
    """
    if isinstance(source, (str, Path)):
        raw = _read_config_file(Path(source))
    else:
        raw = list(source)

    entities = [_to_entity(item, index) for index, item in enumerate(raw)]

    seen: set[str] = set()
    for entity in entities:
        if entity.name in seen:
            raise DomainEntityConfigError(
                f"Domain entity {entity.name!r} is declared more than once. "
                "Give each rule its own name, or combine them into one pattern."
            )
        seen.add(entity.name)

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

    if not isinstance(item, dict):
        raise DomainEntityConfigError(
            f"Entity rule at position {index} must be an object, "
            f"got {type(item).__name__}."
        )

    known = {"name", "pattern", "confidence", "context_words", "context_window"}
    unknown = set(item) - known
    if unknown:
        raise DomainEntityConfigError(
            f"Entity rule at position {index} has unknown field(s): "
            f"{', '.join(sorted(unknown))}. Allowed: {', '.join(sorted(known))}."
        )

    for required in ("name", "pattern"):
        if required not in item:
            raise DomainEntityConfigError(
                f"Entity rule at position {index} is missing {required!r}."
            )

    return DomainEntity(
        name=str(item["name"]),
        pattern=str(item["pattern"]),
        confidence=float(item.get("confidence", DEFAULT_CONFIDENCE)),
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

    Runs alongside the built-in regex layer. Spans are marked
    ``is_regex_validated`` because a configured pattern is an explicit
    statement about this deployment's data — when it overlaps a generic
    built-in match, the specific rule should win.
    """

    def __init__(self, entities: Sequence[DomainEntity]) -> None:
        self._entities = tuple(entities)
        self._types = {
            entity.name: register_entity_type(entity.name) for entity in self._entities
        }
        logger.info(
            "DomainEntityLayer ready (%d rule(s): %s)",
            len(self._entities),
            ", ".join(entity.name for entity in self._entities) or "none",
        )

    @property
    def entities(self) -> tuple[DomainEntity, ...]:
        """The configured rules, in declaration order."""
        return self._entities

    def detect(self, text: str) -> list[DetectedSpan]:
        """Run every configured pattern against the text."""
        spans: list[DetectedSpan] = []

        for entity in self._entities:
            for match in entity.compiled.finditer(text):
                value = match.group()
                if not value:
                    continue

                if entity.context_re is not None and not self._has_context(
                    text, match.start(), match.end(), entity
                ):
                    continue

                spans.append(
                    DetectedSpan(
                        start=match.start(),
                        end=match.end(),
                        text=value,
                        entity_type=self._types[entity.name],
                        confidence=entity.confidence,
                        source=SOURCE,
                        is_regex_validated=True,
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
