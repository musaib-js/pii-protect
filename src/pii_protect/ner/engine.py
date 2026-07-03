"""
pii_shield.ner.engine
=======================
Multi-layer NER engine for PII detection in free-text documents.

Detection layers (applied in order, results merged):
  1. Regex patterns      — high-precision pattern matching for structured PII
     (GST, PAN, IBAN, email, phone, account numbers, etc.). Always available,
     no extra dependencies.
  2. spaCy NER            — lightweight on-premise model (e.g. en_core_web_sm)
     for PERSON, ORG, GPE entity detection. Requires the ``pii-shield[spacy]``
     extra.
  3. Transformer privacy filter — bidirectional token-classification model
     run on-premise via a HuggingFace `transformers.pipeline`
     (task="token-classification", aggregation_strategy="simple"). Requires
     the ``pii-shield[privacy-filter]`` extra.

After detection, the SpanConflictResolver resolves conflicts across all
enabled layers and produces a deduplicated, non-overlapping span list.

Design constraints:
  - No network calls during inference; any model weights are loaded once
    at construction time from local/cached files.
  - All processing is in-memory. No temp files.
  - Thread-safe: each call produces fresh outputs; models are read-only.

Author: Musaib Altaf
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from pii_shield.exceptions import OptionalDependencyMissingError
from pii_shield.types import DetectedSpan, EntityType

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 1: Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

class RegexPatternLibrary:
    """
    High-precision regex patterns for structured PII entities.

    Each pattern is compiled once at import time. Patterns include
    anchors/boundaries where needed to reduce false positives.
    """

    # India-specific
    GST_NUMBER   = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b")
    PAN_NUMBER   = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")
    TAN_NUMBER   = re.compile(r"\b[A-Z]{4}[0-9]{5}[A-Z]{1}\b")

    # International tax
    ABN_NUMBER   = re.compile(r"\bABN\s*:?\s*\d{2}\s*\d{3}\s*\d{3}\s*\d{3}\b", re.IGNORECASE)
    VAT_EU       = re.compile(r"\b[A-Z]{2}\d{8,12}\b")

    # Banking / financial
    IBAN         = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")
    SWIFT_BIC    = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b")
    ACCOUNT_NUM  = re.compile(r"\b(?:A/c|Account|Acc\.?)\s*(?:No\.?|Number)?\s*:?\s*[\d\s\-]{6,20}\b", re.IGNORECASE)
    SORT_CODE    = re.compile(r"\b\d{2}-\d{2}-\d{2}\b")
    ROUTING_NUM  = re.compile(r"\b\d{9}\b")  # ABA routing (must be contextualised)
    CREDIT_CARD  = re.compile(r"\b(?:\d[ -]?){13,16}\b")

    # Contact
    EMAIL        = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
    PHONE_IN     = re.compile(r"(?:\+91|0)?[6-9]\d{9}")  # India mobile
    PHONE_INTL   = re.compile(r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}")

    # Invoice / document references
    INVOICE_REF  = re.compile(r"\b(?:Invoice|Inv)\.?\s*(?:No\.?|Number|#|:)?\s*:?\s*[A-Z0-9\-/]{4,20}\b", re.IGNORECASE)
    PO_REF       = re.compile(r"\b(?:PO|Purchase\s*Order)\.?\s*(?:No\.?|Number|#|:)?\s*:?\s*[A-Z0-9\-/]{4,20}\b", re.IGNORECASE)

    PATTERNS: list[tuple[re.Pattern, EntityType, float]] = []

    @classmethod
    def _build_pattern_list(cls) -> None:
        cls.PATTERNS = [
            (cls.GST_NUMBER,  EntityType.GST,            0.99),
            (cls.PAN_NUMBER,  EntityType.PAN,            0.97),
            (cls.TAN_NUMBER,  EntityType.TAN,            0.92),
            (cls.ABN_NUMBER,  EntityType.ABN,            0.96),
            (cls.VAT_EU,      EntityType.VAT,            0.85),
            (cls.IBAN,        EntityType.IBAN,           0.90),
            (cls.SWIFT_BIC,   EntityType.SWIFT,          0.88),
            (cls.ACCOUNT_NUM, EntityType.ACCOUNT,        0.88),
            (cls.SORT_CODE,   EntityType.SORT_CODE,      0.80),
            (cls.CREDIT_CARD, EntityType.CREDIT_CARD,    0.85),
            (cls.EMAIL,       EntityType.EMAIL,          0.99),
            (cls.PHONE_IN,    EntityType.PHONE,          0.95),
            (cls.PHONE_INTL,  EntityType.PHONE,          0.90),
            (cls.INVOICE_REF, EntityType.INVOICE_NUMBER, 0.80),
            (cls.PO_REF,      EntityType.PO_NUMBER,      0.80),
        ]


RegexPatternLibrary._build_pattern_list()


class RegexNERLayer:
    """Layer 1: regex-based entity detection. No optional dependencies."""

    def detect(self, text: str) -> list[DetectedSpan]:
        """
        Run all compiled regex patterns against the input text.

        Parameters
        ----------
        text : str
            Input text (may be masked text from a prior run; safe to re-run).

        Returns
        -------
        list[DetectedSpan]
            All detected spans, sorted by start offset.
        """
        spans: list[DetectedSpan] = []
        for pattern, entity_type, confidence in RegexPatternLibrary.PATTERNS:
            for match in pattern.finditer(text):
                spans.append(DetectedSpan(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    entity_type=entity_type,
                    confidence=confidence,
                    source="regex",
                    is_regex_validated=True,
                ))
        return sorted(spans, key=lambda s: s.start)


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 2: spaCy NER (optional dependency: pii-shield[spacy])
# ─────────────────────────────────────────────────────────────────────────────

_SPACY_TO_ENTITY = {
    "PERSON":  EntityType.PERSON,
    "ORG":     EntityType.ORGANISATION,
    "GPE":     EntityType.ADDRESS,
    "LOC":     EntityType.ADDRESS,
    "FAC":     EntityType.ADDRESS,
}


class SpacyNERLayer:
    """
    Layer 2: spaCy NER (on-premise). Detects PERSON, ORG, GPE/LOC/FAC.
    Never sends data to any external service.

    Requires the ``pii-shield[spacy]`` extra (spaCy + a language model,
    e.g. ``en_core_web_sm``).
    """

    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        try:
            import spacy
        except ImportError as exc:
            raise OptionalDependencyMissingError("SpacyNERLayer", "spacy", "spacy") from exc

        logger.info("Loading spaCy model: %s", model_name)
        self._nlp = spacy.load(model_name, disable=["parser", "lemmatizer"])
        logger.info("spaCy model loaded.")

    def detect(self, text: str) -> list[DetectedSpan]:
        """
        Run the spaCy NER pipeline on the input text.

        Parameters
        ----------
        text : str
            Input document text.

        Returns
        -------
        list[DetectedSpan]
            Spans for PERSON, ORG, GPE/LOC/FAC entities.
        """
        doc = self._nlp(text)
        spans: list[DetectedSpan] = []
        for ent in doc.ents:
            entity_type = _SPACY_TO_ENTITY.get(ent.label_)
            if entity_type is None:
                continue
            spans.append(DetectedSpan(
                start=ent.start_char,
                end=ent.end_char,
                text=ent.text,
                entity_type=entity_type,
                confidence=0.75,   # spaCy doesn't expose per-ent confidence; fixed prior
                source="spacy",
            ))
        return spans


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 3: transformer-based privacy filter (optional dependency)
# ─────────────────────────────────────────────────────────────────────────────

_PRIVACY_FILTER_LABEL_TO_ENTITY = {
    "private_person":  EntityType.PERSON,
    "private_address": EntityType.ADDRESS,
    "private_email":   EntityType.EMAIL,
    "private_phone":   EntityType.PHONE,
    "account_number":  EntityType.ACCOUNT,
    "private_url":     EntityType.OTHER,
    "private_date":    EntityType.OTHER,
    "secret":          EntityType.OTHER,
}


class PrivacyFilterLayer:
    """
    Layer 3: transformer-based token-classification privacy filter, run
    on-premise via a HuggingFace `transformers` pipeline.

    Requires the ``pii-shield[privacy-filter]`` extra (transformers + torch).

    TokenizerSafeSpanMerger is applied as a defensive second pass: in rare
    cases (very long entities split across a model's attention window, or
    subword artefacts at chunk boundaries) the pipeline can emit adjacent
    same-type spans that should be one entity.
    """

    def __init__(
        self,
        model_name: str,
        threshold: float = 0.50,
        device: str = "cpu",
        max_chars_per_chunk: int = 4000,
    ) -> None:
        """
        Load a token-classification model via the HuggingFace pipeline.

        Parameters
        ----------
        model_name : str
            HuggingFace model identifier (e.g. an on-premise privacy/PII
            token-classification model of your choosing).
        threshold : float
            Minimum pipeline `score` for an entity span to be accepted.
        device : str
            'cpu' or 'cuda' (or a CUDA device index understood by transformers).
        max_chars_per_chunk : int
            Defensive chunk size to bound peak memory on very large inputs.
        """
        try:
            from transformers import pipeline as hf_pipeline
        except ImportError as exc:
            raise OptionalDependencyMissingError(
                "PrivacyFilterLayer", "privacy-filter", "transformers"
            ) from exc

        logger.info("Loading transformer privacy-filter model: %s (device=%s)", model_name, device)
        device_arg = -1 if device == "cpu" else device
        self._pipeline = hf_pipeline(
            task="token-classification",
            model=model_name,
            aggregation_strategy="simple",
            device=device_arg,
            trust_remote_code=True,
        )
        self._threshold = threshold
        self._max_chars = max_chars_per_chunk
        self._merger = TokenizerSafeSpanMerger()
        logger.info("Transformer privacy-filter model loaded.")

    def detect(self, text: str) -> list[DetectedSpan]:
        """
        Run the token-classification pipeline on the input text.

        Parameters
        ----------
        text : str
            Input document text. Chunked defensively for very large inputs.

        Returns
        -------
        list[DetectedSpan]
            Detected entity spans from the transformer model.
        """
        if not text.strip():
            return []

        chunks = self._chunk_text(text, max_chars=self._max_chars)
        all_spans: list[DetectedSpan] = []
        offset = 0

        for chunk in chunks:
            raw_entities = self._pipeline(chunk)
            for ent in raw_entities:
                score = float(ent["score"])
                if score < self._threshold:
                    continue
                entity_type = _PRIVACY_FILTER_LABEL_TO_ENTITY.get(
                    ent["entity_group"], EntityType.OTHER
                )
                all_spans.append(DetectedSpan(
                    start=offset + ent["start"],
                    end=offset + ent["end"],
                    text=ent["word"],
                    entity_type=entity_type,
                    confidence=score,
                    source="privacy_filter",
                ))
            offset += len(chunk)

        return self._merger.merge(all_spans)

    def _chunk_text(self, text: str, max_chars: int = 4000) -> list[str]:
        """Split text into chunks, breaking at paragraph/sentence boundaries where possible."""
        if len(text) <= max_chars:
            return [text]

        chunks: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + max_chars, len(text))
            para_break = text.rfind("\n\n", start, end)
            if para_break > start:
                end = para_break + 2
            else:
                sent_break = text.rfind(". ", start, end)
                if sent_break > start:
                    end = sent_break + 2
            chunks.append(text[start:end])
            start = end
        return chunks


# ─────────────────────────────────────────────────────────────────────────────
#  Tokenizer-safe span merger  (B/I/E token boundary handling)
# ─────────────────────────────────────────────────────────────────────────────

class TokenizerSafeSpanMerger:
    """
    Merges B/I/E token-boundary artefacts into complete entity spans.

    Some token-classification models emit separate spans for sub-word
    tokens of the same entity; this merger reassembles them into complete
    surface-form spans. Also usable as a general-purpose span deduplicator.
    """

    def merge(self, spans: list[DetectedSpan]) -> list[DetectedSpan]:
        """
        Merge adjacent/overlapping spans of the same entity type that are
        contiguous in the text (no gap > 2 characters between them).

        Parameters
        ----------
        spans : list[DetectedSpan]
            Raw spans from a NER model, possibly with B/I/E artefacts.

        Returns
        -------
        list[DetectedSpan]
            Merged, deduplicated spans.
        """
        if not spans:
            return []

        sorted_spans = sorted(spans, key=lambda s: (s.start, s.entity_type))
        merged: list[DetectedSpan] = []
        current = sorted_spans[0]

        for nxt in sorted_spans[1:]:
            gap = nxt.start - current.end
            if nxt.entity_type == current.entity_type and nxt.source == current.source and gap <= 2:
                current = DetectedSpan(
                    start=current.start,
                    end=nxt.end,
                    text=current.text + (" " if gap > 0 else "") + nxt.text,
                    entity_type=current.entity_type,
                    confidence=max(current.confidence, nxt.confidence),
                    source=current.source,
                    is_regex_validated=current.is_regex_validated or nxt.is_regex_validated,
                )
            else:
                merged.append(current)
                current = nxt

        merged.append(current)
        return merged


# ─────────────────────────────────────────────────────────────────────────────
#  Span conflict resolver
# ─────────────────────────────────────────────────────────────────────────────

_FINANCIAL_ENTITIES = {
    EntityType.ACCOUNT,
    EntityType.IBAN,
    EntityType.SWIFT,
    EntityType.TAX_ID,
    EntityType.GST,
    EntityType.PAN,
    EntityType.TAN,
    EntityType.ABN,
    EntityType.VAT,
    EntityType.SORT_CODE,
    EntityType.ROUTING_NUMBER,
    EntityType.CREDIT_CARD,
    EntityType.BANK_ACCOUNT,
}


class SpanConflictResolver:
    """
    Resolves conflicts between DetectedSpan objects from different NER layers.

    Conflict resolution priority rules (applied in order):
      1. Regex-validated spans always win over non-validated spans.
      2. Higher confidence wins (when not regex-validated).
      3. Longer span wins (when confidence is equal within 0.05).
      4. Financial entity types override PHONE in overlapping spans.
      5. Duplicate entity (same start, end, entity_type) removed.
      6. Remaining overlapping spans: keep the highest-priority span.

    After resolution, the output is a non-overlapping, deduplicated
    list of DetectedSpan objects, sorted by start offset.
    """

    def resolve(self, all_spans: list[DetectedSpan]) -> list[DetectedSpan]:
        """
        Merge spans from all NER layers into a single non-overlapping list.

        Parameters
        ----------
        all_spans : list[DetectedSpan]
            Combined spans from every enabled detection layer.

        Returns
        -------
        list[DetectedSpan]
            Non-overlapping, deduplicated, priority-resolved spans.
        """
        if not all_spans:
            return []

        deduped = self._remove_duplicates(all_spans)
        sorted_spans = sorted(deduped, key=lambda s: (s.start, -self._priority(s)))

        resolved: list[DetectedSpan] = []
        for span in sorted_spans:
            if not resolved:
                resolved.append(span)
                continue

            last = resolved[-1]
            if not span.overlaps(last):
                resolved.append(span)
            else:
                winner = self._pick_winner(last, span)
                if winner is not last:
                    resolved[-1] = winner

        return sorted(resolved, key=lambda s: s.start)

    def _priority(self, span: DetectedSpan) -> float:
        """
        Compute a numeric priority for a span.

        Priority formula:
          base = confidence
          + 0.30 if regex_validated
          + 0.10 if financial entity
          + 0.001 * length (tie-breaker for longer spans)
        """
        score = span.confidence
        if span.is_regex_validated:
            score += 0.30
        if span.entity_type in _FINANCIAL_ENTITIES:
            score += 0.10
        score += 0.001 * span.length
        return score

    def _pick_winner(self, a: DetectedSpan, b: DetectedSpan) -> DetectedSpan:
        """
        Choose between two overlapping spans.

        Rules (in order):
          1. Regex-validated beats non-validated.
          2. Financial entity beats PHONE.
          3. Higher confidence wins.
          4. Longer span wins.
          5. If still equal, keep the first (a).
        """
        if a.is_regex_validated and not b.is_regex_validated:
            return a
        if b.is_regex_validated and not a.is_regex_validated:
            return b

        if a.entity_type in _FINANCIAL_ENTITIES and b.entity_type == EntityType.PHONE:
            return a
        if b.entity_type in _FINANCIAL_ENTITIES and a.entity_type == EntityType.PHONE:
            return b

        if abs(a.confidence - b.confidence) > 0.05:
            return a if a.confidence > b.confidence else b

        return a if a.length >= b.length else b

    def _remove_duplicates(self, spans: list[DetectedSpan]) -> list[DetectedSpan]:
        """Remove exact duplicate spans (same start, end, entity_type), keeping the highest priority."""
        seen: dict[tuple, DetectedSpan] = {}
        for span in spans:
            key = (span.start, span.end, span.entity_type)
            if key not in seen or self._priority(span) > self._priority(seen[key]):
                seen[key] = span
        return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
#  NEREngine  (public interface — composes all enabled layers)
# ─────────────────────────────────────────────────────────────────────────────

class NEREngine:
    """
    Top-level NER engine composing regex, spaCy, and transformer
    privacy-filter detection layers.

    Usage
    -----
    ::

        engine = NEREngine()   # regex only, no extra dependencies
        spans = engine.detect("Invoice from Acme Corp, GST: 27AAPFU0939F1ZV")

        # with spaCy (requires pii-shield[spacy]):
        engine = NEREngine(enable_spacy=True)

    Attributes
    ----------
    _regex_layer : RegexNERLayer
    _spacy_layer : Optional[SpacyNERLayer]
    _privacy_filter_layer : Optional[PrivacyFilterLayer]
    _merger : TokenizerSafeSpanMerger
    _resolver : SpanConflictResolver
    """

    def __init__(
        self,
        enable_spacy: bool = False,
        spacy_model: str = "en_core_web_sm",
        enable_privacy_filter: bool = False,
        privacy_filter_model: Optional[str] = None,
        privacy_filter_threshold: float = 0.50,
        privacy_filter_device: str = "cpu",
    ) -> None:
        """
        Initialise the enabled NER layers. Models are loaded once and reused.

        Parameters
        ----------
        enable_spacy : bool
            Enable the spaCy layer (PERSON/ORG/GPE detection). Requires
            the ``pii-shield[spacy]`` extra.
        spacy_model : str
            spaCy model name (must be installed).
        enable_privacy_filter : bool
            Enable the transformer token-classification layer. Requires
            the ``pii-shield[privacy-filter]`` extra.
        privacy_filter_model : Optional[str]
            HuggingFace model identifier. Required if
            ``enable_privacy_filter=True``.
        privacy_filter_threshold : float
            Minimum pipeline `score` for an entity span to be accepted.
        privacy_filter_device : str
            'cpu' or 'cuda'.
        """
        self._regex_layer = RegexNERLayer()
        self._spacy_layer = SpacyNERLayer(spacy_model) if enable_spacy else None

        self._privacy_filter_layer: Optional[PrivacyFilterLayer] = None
        if enable_privacy_filter:
            if not privacy_filter_model:
                raise ValueError("privacy_filter_model is required when enable_privacy_filter=True")
            self._privacy_filter_layer = PrivacyFilterLayer(
                privacy_filter_model, privacy_filter_threshold, privacy_filter_device
            )

        self._merger = TokenizerSafeSpanMerger()
        self._resolver = SpanConflictResolver()
        logger.info(
            "NEREngine ready (layers: regex, spacy=%s, privacy_filter=%s)",
            spacy_model if enable_spacy else "DISABLED",
            privacy_filter_model if enable_privacy_filter else "DISABLED",
        )

    def detect(self, text: str) -> list[DetectedSpan]:
        """
        Run all enabled detection layers and return merged, conflict-resolved spans.

        Parameters
        ----------
        text : str
            Input document text (should be normalised plain text).

        Returns
        -------
        list[DetectedSpan]
            Non-overlapping PII entity spans, sorted by start offset.
        """
        if not text.strip():
            return []

        regex_spans = self._regex_layer.detect(text)
        spacy_spans = self._spacy_layer.detect(text) if self._spacy_layer else []
        privacy_filter_spans = (
            self._privacy_filter_layer.detect(text) if self._privacy_filter_layer else []
        )

        all_spans = regex_spans + spacy_spans + privacy_filter_spans
        resolved = self._resolver.resolve(all_spans)

        logger.debug(
            "NEREngine.detect: regex=%d spacy=%d privacy_filter=%d resolved=%d",
            len(regex_spans), len(spacy_spans), len(privacy_filter_spans), len(resolved),
        )
        return resolved
