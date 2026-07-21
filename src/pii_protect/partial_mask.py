"""
pii_protect.partial_mask
==========================
Partial masking: a display-only rendering that shows part of a detected
PII value (e.g. "the last 6 digits of an account number") instead of an
opaque {{TYPE:xxxx}} token or a fully redacted marker.

This is intentionally NOT part of mask()/unmask(): it never touches the
storage backend, the cipher, or the token generator. It's a pure string
transform that takes an already-computed ``MaskResult`` (from a normal,
unmodified ``engine.mask()`` call) plus the original text, and re-renders
each detected span according to a per-entity-type rule — so a bank can
show "customer-safe" partially-masked documents for display/print
purposes while the underlying reversible mask()/unmask() flow, vault
schema, and token format are completely unchanged.

Usage
-----
::

    result = await engine.mask(text, scope="acct-9001")   # unchanged flow
    partial = engine.render_partial_mask(text, result, rules={
        "ACCOUNT": PartialMaskRule(visible_chars=6, position="end"),
        "PHONE":   PartialMaskRule(visible_chars=4, position="end"),
        "EMAIL":   PartialMaskRule(visible_chars=3, position="start"),
    })
    # "Please debit account **************903456, contact ****@acme.com"

Entity types with no configured rule fall back to full masking
(every character replaced), so nothing is accidentally left more visible
than intended just because a rule wasn't specified for it.

Author: Musaib Altaf
"""

from __future__ import annotations

from typing import Union

from pii_protect.types import DetectedEntityInfo, EntityType, PartialMaskRule

_RuleKey = Union[str, EntityType]


def _normalise_rules(rules: dict) -> dict[str, PartialMaskRule]:
    """Accept rule keys as either EntityType or plain strings, normalised to EntityType.value strings."""
    normalised: dict[str, PartialMaskRule] = {}
    for key, rule in rules.items():
        normalised[key.value if isinstance(key, EntityType) else key] = rule
    return normalised


def _apply_rule(value: str, rule: PartialMaskRule) -> str:
    """Render one detected value according to a PartialMaskRule."""
    visible = max(0, min(rule.visible_chars, len(value)))
    masked_len = len(value) - visible

    if visible == 0:
        return rule.mask_char * len(value)
    if rule.position == "start":
        return value[:visible] + rule.mask_char * masked_len
    return rule.mask_char * masked_len + value[len(value) - visible:]


def render_partial_mask(
    original_text: str,
    entities: list[DetectedEntityInfo],
    rules: dict,
    default_mask_char: str = "*",
) -> str:
    """
    Build a partially-masked rendering of ``original_text``.

    Parameters
    ----------
    original_text : str
        The ORIGINAL plain text passed to ``mask()`` — not its
        ``masked_text``. The offsets in ``entities`` index into this string.
    entities : list[DetectedEntityInfo]
        ``MaskResult.entities`` from the corresponding ``mask()`` call.
    rules : dict[str | EntityType, PartialMaskRule]
        Mapping of entity type (as an ``EntityType`` or its ``.value``
        string, e.g. ``"ACCOUNT"``) to a ``PartialMaskRule``. Entity
        types with no rule configured are fully masked.
    default_mask_char : str
        Mask character used for entity types with no configured rule.

    Returns
    -------
    str
        ``original_text`` with every detected span replaced by its
        partial (or full) mask rendering.
    """
    normalised_rules = _normalise_rules(rules)
    result_text = original_text

    for entity in sorted(entities, key=lambda e: e.start, reverse=True):
        original_value = original_text[entity.start:entity.end]
        rule = normalised_rules.get(entity.entity_type)
        rendered = _apply_rule(original_value, rule) if rule else default_mask_char * len(original_value)
        result_text = result_text[:entity.start] + rendered + result_text[entity.end:]

    return result_text
