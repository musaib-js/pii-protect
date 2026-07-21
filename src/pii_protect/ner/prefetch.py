"""
pii_protect.ner.prefetch
=========================
Optional model-prefetch helpers.

pii_protect never downloads model weights on its own — GLiNERLayer and
PrivacyFilterLayer default to offline-safe loading and raise immediately
if weights aren't already cached. These functions exist so that whatever
provisioning step *your* application already uses (a Docker build stage,
a CI step, a one-off setup script — pii_protect has no opinion on which)
can warm that cache explicitly, once, ahead of time — only for the
optional layers you've actually chosen to enable.

Author: Musaib Altaf
"""

from __future__ import annotations

from pii_protect.exceptions import OptionalDependencyMissingError


def prefetch_gliner(model_name: str = "gliner-community/gliner_small-v2.5") -> None:
    """
    Download and cache GLiNER model weights. Requires ``pii-shield[gliner]``.

    Call this explicitly from your own build/provisioning step before
    constructing ``NEREngine(enable_gliner=True)`` — pii_protect never
    calls it for you.
    """
    try:
        from gliner import GLiNER
    except ImportError as exc:
        raise OptionalDependencyMissingError("prefetch_gliner", "gliner", "gliner") from exc

    GLiNER.from_pretrained(model_name)


def prefetch_privacy_filter(model_name: str) -> None:
    """
    Download and cache a transformers token-classification model.
    Requires ``pii-shield[privacy-filter]``.

    Call this explicitly from your own build/provisioning step before
    constructing ``NEREngine(enable_privacy_filter=True, privacy_filter_model=...)``.
    """
    try:
        from transformers import AutoModelForTokenClassification, AutoTokenizer
    except ImportError as exc:
        raise OptionalDependencyMissingError(
            "prefetch_privacy_filter", "privacy-filter", "transformers"
        ) from exc

    AutoTokenizer.from_pretrained(model_name)
    AutoModelForTokenClassification.from_pretrained(model_name)
