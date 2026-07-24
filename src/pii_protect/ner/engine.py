"""
pii_protect.ner.engine
=======================
Multi-layer NER engine for PII detection in free-text documents.

Detection layers (applied in order, results merged):
  1. Regex patterns      — high-precision pattern matching for structured PII
     (GST, PAN, IBAN, email, phone, account numbers, etc.). Always available,
     no extra dependencies.
  2. GLiNER               — zero-shot on-premise NER (person/org/address/
     passport/driving-license/username/etc.). Requires the
     ``pii-protect[gliner]`` extra.
  3. spaCy NER            — lightweight on-premise model (e.g. en_core_web_sm)
     for PERSON, ORG, GPE entity detection. Requires the ``pii-protect[spacy]``
     extra.
  4. Transformer privacy filter — bidirectional token-classification model
     run on-premise via a HuggingFace `transformers.pipeline`
     (task="token-classification", aggregation_strategy="simple"). Requires
     the ``pii-protect[privacy-filter]`` extra.

After detection, the SpanConflictResolver resolves conflicts across all
enabled layers and produces a deduplicated, non-overlapping span list.

Design constraints:
  - No network calls during inference; any model weights are loaded once
    at construction time from local/cached files (GLiNER/spaCy/transformer
    layers default to offline-safe loading — see their constructors).
  - All processing is in-memory. No temp files.
  - Thread-safe: each call produces fresh outputs; models are read-only.

Author: Musaib Altaf
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from pii_protect.exceptions import InvalidInputError, OptionalDependencyMissingError
from pii_protect.types import DetectedSpan, EntityType

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 1: Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# ISO 3166-1 alpha-2 country codes — used to validate the country-code
# segment of a SWIFT/BIC candidate (positions 5-6) instead of accepting
# any two uppercase letters, which false-positives on ordinary 8-letter
# English words (see V-13 in the security review).
_ISO_3166_ALPHA2 = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())

# Common UPI (India) PSP handles — used to validate the suffix of a UPI ID
# instead of accepting any "word@word" token, which false-positives on
# ordinary internal identifiers like "user@internal" (see V-18).
_UPI_HANDLES = (
    "oksbi|ybl|okhdfcbank|okicici|okaxis|paytm|apl|ibl|axl|jio|freecharge|"
    "rapl|yesbank|axisbank|sbi|hdfcbank|icici|kotak|indus|upi|okbizaxis|"
    "idfcfirst|federal|cnrb|barodampay|pockets|airtel"
)

# How close a "SWIFT"/"BIC" label must appear before a candidate code for it
# to be accepted (V-13) -- covers "SWIFT: DEUTDEFF", "BIC DEUTDEFF", "Bank
# SWIFT code: DEUTDEFF", etc. without requiring an exact adjacency.
_SWIFT_CONTEXT_WINDOW = 25
_SWIFT_CONTEXT_RE = re.compile(r"\b(?:swift|bic)\b", re.IGNORECASE)


def _luhn_is_valid(digits: str) -> bool:
    """
    Validate a digit string against the Luhn checksum (used to filter the
    CREDIT_CARD pattern — see V-12). Returns False for anything that isn't
    a plausible card number, including sequences that merely look like one.
    """
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class RegexPatternLibrary:
    """
    High-precision regex patterns for structured PII entities.

    Each pattern is compiled once at import time. Patterns include
    anchors/boundaries where needed to reduce false positives.
    """

    # India-specific
    GST_NUMBER = re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b")
    PAN_NUMBER = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")
    TAN_NUMBER = re.compile(r"\b[A-Z]{4}[0-9]{5}[A-Z]{1}\b")
    IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

    # International tax / company registration
    ABN_NUMBER = re.compile(
        r"\bABN\s*:?\s*\d{2}\s*\d{3}\s*\d{3}\s*\d{3}\b", re.IGNORECASE
    )
    VAT_EU = re.compile(r"\b[A-Z]{2}\d{8,12}\b")
    UEN_NUMBER = re.compile(r"\bUEN\d{9,10}[A-Z]\b")
    CRN_NUMBER = re.compile(r"\bCRN-\d{6,}\b")

    # Banking / financial
    IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")
    SWIFT_BIC = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b")
    ACCOUNT_NUM = re.compile(
        r"\b(?:A/c|Account|Acc\.?)\s*(?:No\.?|Number)?\s*:?\s*[\d\s\-]{6,20}\b",
        re.IGNORECASE,
    )
    ACCOUNT_NUM_HYPHENATED = re.compile(r"\b\d{3}-\d{5}-\d{1}\b")
    SORT_CODE = re.compile(r"\b\d{2}-\d{2}-\d{2}\b")
    CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")

    # Contact
    # Allows a small amount of whitespace around '@' -- "john @ acme.com" is a
    # realistic OCR/manual-entry artefact, not a different kind of value; the
    # unmasked entity_type is still EMAIL either way (V-8 residual).
    EMAIL = re.compile(
        r"\b[a-zA-Z0-9._%+\-]+\s{0,2}@\s{0,2}[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    )
    UPI = re.compile(rf"\b[\w.\-]{{2,64}}@(?:{_UPI_HANDLES})\b", re.IGNORECASE)
    PHONE_IN = re.compile(r"\b(?:\+91|0)?[6-9]\d{9}\b")  # India mobile, contiguous
    PHONE_IN_SPACED = re.compile(
        r"\b(?:\+91[-\s]?)?[6-9]\d{4}[-\s]\d{5}\b"
    )  # India mobile, "98765 43210" (V-16)
    PHONE_INTL = re.compile(
        r"\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}"
    )
    PHONE_US = re.compile(
        r"(?:\+1-?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
    )  # requires a separator between all 3 groups
    PHONE_PARENS = re.compile(
        r"\(\d{3,6}\)\s?\d{3,8}\b"
    )  # "(98765)43210" (V-8 residual)

    # Invoice / document references
    INVOICE_REF = re.compile(
        r"\b(?:Invoice|Inv)\.?\s*(?:No\.?|Number|#|:)?\s*:?\s*[A-Z0-9\-/]{4,20}\b",
        re.IGNORECASE,
    )
    PO_REF = re.compile(
        r"\b(?:PO|Purchase\s*Order)\.?\s*(?:No\.?|Number|#|:)?\s*:?\s*[A-Z0-9\-/]{4,20}\b",
        re.IGNORECASE,
    )

    # URL
    URL = re.compile(r"\bhttps?://[^\s/$.?#].[^\s]*\b", re.IGNORECASE)
    URL_NO_PROTOCOL = re.compile(r"\b(?:www\.)[^\s/$.?#].[^\s]*\b", re.IGNORECASE)
    URL_FTP = re.compile(r"\bftp://[^\s/$.?#].[^\s]*\b", re.IGNORECASE)

    PATTERNS: list[tuple[re.Pattern, EntityType, float]] = []

    @classmethod
    def _build_pattern_list(cls) -> None:
        cls.PATTERNS = [
            (cls.GST_NUMBER, EntityType.GST, 0.99),
            (cls.PAN_NUMBER, EntityType.PAN, 0.97),
            (cls.TAN_NUMBER, EntityType.TAN, 0.92),
            (cls.IFSC, EntityType.IFSC, 0.90),
            (cls.ABN_NUMBER, EntityType.ABN, 0.96),
            (cls.UEN_NUMBER, EntityType.UEN, 0.90),
            (cls.CRN_NUMBER, EntityType.CRN, 0.90),
            (cls.VAT_EU, EntityType.VAT, 0.85),
            (cls.IBAN, EntityType.IBAN, 0.90),
            (
                cls.SWIFT_BIC,
                EntityType.SWIFT,
                0.88,
            ),  # post-filtered by country code, see below
            (cls.ACCOUNT_NUM, EntityType.ACCOUNT, 0.88),
            (cls.ACCOUNT_NUM_HYPHENATED, EntityType.ACCOUNT, 0.85),
            (cls.SORT_CODE, EntityType.SORT_CODE, 0.80),
            (
                cls.CREDIT_CARD,
                EntityType.CREDIT_CARD,
                0.85,
            ),  # post-filtered by Luhn, see below
            (cls.EMAIL, EntityType.EMAIL, 0.99),
            (cls.UPI, EntityType.UPI, 0.85),
            (cls.PHONE_IN, EntityType.PHONE, 0.95),
            (cls.PHONE_IN_SPACED, EntityType.PHONE, 0.85),
            (cls.PHONE_INTL, EntityType.PHONE, 0.90),
            (cls.PHONE_US, EntityType.PHONE, 0.85),
            (cls.PHONE_PARENS, EntityType.PHONE, 0.80),
            (cls.INVOICE_REF, EntityType.INVOICE_NUMBER, 0.80),
            (cls.PO_REF, EntityType.PO_NUMBER, 0.80),
            (cls.URL, EntityType.URL, 0.85),
            (cls.URL_NO_PROTOCOL, EntityType.URL, 0.80),
            (cls.URL_FTP, EntityType.URL, 0.80),
        ]


RegexPatternLibrary._build_pattern_list()


class RegexNERLayer:
    """
    Layer 1: regex-based entity detection. No optional dependencies.

    Two patterns get a semantic post-filter beyond the raw regex match,
    because a shape match alone is too permissive:
      - CREDIT_CARD candidates must pass a Luhn checksum (V-12): a
        sequential or all-zero 13-19 digit run is not a real card number.
      - SWIFT/BIC candidates must (a) have a valid ISO 3166-1 country
        code in positions 5-6, AND (b) appear within a short window of
        a "SWIFT"/"BIC" label in the surrounding text (V-13). The
        country-code check alone isn't enough: with 249 valid codes out
        of 676 possible two-letter combinations, roughly a third of
        random 8-letter ALL-CAPS words coincidentally land on a real
        code (CHECKING -> "KI", SHIPMENT -> "ME", DEADLINE -> "LI" all
        pass the country-code check on their own). Requiring a nearby
        label is how real-world SWIFT extraction narrows this down in
        practice, and matches how these codes actually appear in
        business documents ("SWIFT: DEUTDEFF", "BIC DEUTDEFF").

    Note on PHONE patterns deliberately NOT included here: an earlier
    bare-7-digit pattern (`\\d{3}[-.\\s]?\\d{4}`) was removed. It both
    false-positived on ordinary business numerics (order numbers,
    reference IDs) and — worse — sometimes matched only a *fragment* of
    a longer spaced phone number, leaving real digits outside the match
    unmasked while a "[REDACTED:PHONE]" marker sat right next to them,
    which looked handled but wasn't (V-16/V-17). The remaining phone
    patterns require a real separator/prefix structure. Bare-digit
    phone formats without any separator or country code (e.g. a raw
    10-digit run with no `+`/hyphen/space anywhere) are a known regex-
    layer coverage gap — enable the spaCy/GLiNER/privacy-filter layers
    for better recall on those.
    """

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
                value = match.group()

                if entity_type == EntityType.CREDIT_CARD:
                    stripped = re.sub(r"[ \-]", "", value)
                    if not _luhn_is_valid(stripped):
                        continue

                if entity_type == EntityType.SWIFT:
                    if len(value) not in (8, 11) or value[4:6] not in _ISO_3166_ALPHA2:
                        continue
                    window_start = max(0, match.start() - _SWIFT_CONTEXT_WINDOW)
                    context = text[window_start : match.start()]
                    if not _SWIFT_CONTEXT_RE.search(context):
                        continue

                spans.append(
                    DetectedSpan(
                        start=match.start(),
                        end=match.end(),
                        text=value,
                        entity_type=entity_type,
                        confidence=confidence,
                        source="regex",
                        is_regex_validated=True,
                    )
                )
        return sorted(spans, key=lambda s: s.start)


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 2: GLiNER (optional dependency: pii-protect[gliner])
# ─────────────────────────────────────────────────────────────────────────────

_GLINER_TO_ENTITY = {
    "person": EntityType.PERSON,
    "organization": EntityType.ORGANISATION,
    "company": EntityType.ORGANISATION,
    "address": EntityType.ADDRESS,
    "location": EntityType.ADDRESS,
    "hospital": EntityType.ORGANISATION,
    "school": EntityType.ORGANISATION,
    "university": EntityType.ORGANISATION,
    "government organization": EntityType.ORGANISATION,
    "passport": EntityType.PASSPORT,
    "driving license": EntityType.DRIVING_LICENSE,
    "username": EntityType.USERNAME,
    "customer name": EntityType.PERSON,
    "vendor name": EntityType.ORGANISATION,
    "ifsc code": EntityType.IFSC,
}


class GLiNERLayer:
    """
    Layer 2: GLiNER zero-shot Named Entity Recognition, run fully on-premise.

    Requires the ``pii-protect[gliner]`` extra.

    Model loading defaults to OFFLINE (``local_files_only=True``): if the
    model weights aren't already cached locally, construction raises
    immediately with a clear error rather than silently reaching out to
    the Hub. Warm the cache ahead of time with
    ``pii_protect.ner.prefetch.prefetch_gliner()``, called from whatever
    provisioning step your application already uses (this library never
    calls it automatically).
    """

    DEFAULT_LABELS = (
        "person",
        "organization",
        "company",
        "address",
        "location",
        "hospital",
        "school",
        "university",
        "government organization",
        "passport",
        "driving license",
        "username",
        "customer name",
        "vendor name",
        "ifsc code",
    )

    def __init__(
        self,
        model_name: str = "gliner-community/gliner_small-v2.5",
        threshold: float = 0.60,
        labels: Optional[tuple[str, ...]] = None,
        max_chars_per_chunk: int = 4000,
        local_files_only: bool = True,
    ) -> None:
        try:
            from gliner import GLiNER
        except ImportError as exc:
            raise OptionalDependencyMissingError(
                "GLiNERLayer", "gliner", "gliner"
            ) from exc

        logger.info(
            "Loading GLiNER model: %s (local_files_only=%s)",
            model_name,
            local_files_only,
        )
        self._model = GLiNER.from_pretrained(
            model_name, local_files_only=local_files_only
        )
        self._threshold = threshold
        self._labels = labels or self.DEFAULT_LABELS
        self._max_chars = max_chars_per_chunk
        logger.info("GLiNER model loaded.")

    def detect(self, text: str) -> list[DetectedSpan]:
        """Run GLiNER against the input text."""
        if not text.strip():
            return []

        spans: list[DetectedSpan] = []
        offset = 0
        for chunk in self._chunk_text(text, self._max_chars):
            entities = self._model.predict_entities(
                chunk, labels=self._labels, threshold=self._threshold
            )
            for entity in entities:
                entity_type = _GLINER_TO_ENTITY.get(
                    entity["label"].lower(), EntityType.OTHER
                )
                spans.append(
                    DetectedSpan(
                        start=offset + entity["start"],
                        end=offset + entity["end"],
                        text=entity["text"],
                        entity_type=entity_type,
                        confidence=float(entity["score"]),
                        source="gliner",
                    )
                )
            offset += len(chunk)
        return sorted(spans, key=lambda span: span.start)

    def _chunk_text(self, text: str, max_chars: int) -> list[str]:
        """Split large documents while attempting to preserve sentence/paragraph boundaries."""
        if len(text) <= max_chars:
            return [text]
        chunks: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + max_chars, len(text))
            paragraph_break = text.rfind("\n\n", start, end)
            if paragraph_break > start:
                end = paragraph_break + 2
            else:
                sentence_break = text.rfind(". ", start, end)
                if sentence_break > start:
                    end = sentence_break + 2
            chunks.append(text[start:end])
            start = end
        return chunks


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 3: spaCy NER (optional dependency: pii-protect[spacy])
# ─────────────────────────────────────────────────────────────────────────────

_SPACY_TO_ENTITY = {
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORGANISATION,
    "GPE": EntityType.ADDRESS,
    "LOC": EntityType.ADDRESS,
    "FAC": EntityType.ADDRESS,
}


class SpacyNERLayer:
    """
    Layer 3: spaCy NER (on-premise). Detects PERSON, ORG, GPE/LOC/FAC.
    Never sends data to any external service.

    Requires the ``pii-protect[spacy]`` extra (spaCy + a language model,
    e.g. ``en_core_web_sm``, must already be installed/downloaded).
    """

    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        try:
            import spacy
        except ImportError as exc:
            raise OptionalDependencyMissingError(
                "SpacyNERLayer", "spacy", "spacy"
            ) from exc

        logger.info("Loading spaCy model: %s", model_name)
        self._nlp = spacy.load(model_name, disable=["parser", "lemmatizer"])
        logger.info("spaCy model loaded.")

    def detect(self, text: str) -> list[DetectedSpan]:
        """Run the spaCy NER pipeline on the input text."""
        doc = self._nlp(text)
        spans: list[DetectedSpan] = []
        for ent in doc.ents:
            entity_type = _SPACY_TO_ENTITY.get(ent.label_)
            if entity_type is None:
                continue
            spans.append(
                DetectedSpan(
                    start=ent.start_char,
                    end=ent.end_char,
                    text=ent.text,
                    entity_type=entity_type,
                    confidence=0.75,  # spaCy doesn't expose per-ent confidence; fixed prior
                    source="spacy",
                )
            )
        return spans


# ─────────────────────────────────────────────────────────────────────────────
#  Layer 4: transformer-based privacy filter (optional dependency)
# ─────────────────────────────────────────────────────────────────────────────

_PRIVACY_FILTER_LABEL_TO_ENTITY = {
    "private_person": EntityType.PERSON,
    "private_address": EntityType.ADDRESS,
    "private_email": EntityType.EMAIL,
    "private_phone": EntityType.PHONE,
    "account_number": EntityType.ACCOUNT,
    "private_url": EntityType.OTHER,
    "private_date": EntityType.OTHER,
    "secret": EntityType.OTHER,
}


class PrivacyFilterLayer:
    """
    Layer 4: transformer-based token-classification privacy filter, run
    on-premise via a HuggingFace `transformers` pipeline.

    Requires the ``pii-protect[privacy-filter]`` extra (transformers + torch).
    """

    def __init__(
        self,
        model_name: str,
        threshold: float = 0.50,
        device: str = "cpu",
        max_chars_per_chunk: int = 4000,
    ) -> None:
        try:
            from transformers import pipeline as hf_pipeline
        except ImportError as exc:
            raise OptionalDependencyMissingError(
                "PrivacyFilterLayer", "privacy-filter", "transformers"
            ) from exc

        logger.info(
            "Loading transformer privacy-filter model: %s (device=%s)",
            model_name,
            device,
        )
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
        """Run the token-classification pipeline on the input text."""
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
                all_spans.append(
                    DetectedSpan(
                        start=offset + ent["start"],
                        end=offset + ent["end"],
                        text=ent["word"],
                        entity_type=entity_type,
                        confidence=score,
                        source="privacy_filter",
                    )
                )
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
        """
        if not spans:
            return []

        sorted_spans = sorted(spans, key=lambda s: (s.start, s.entity_type))
        merged: list[DetectedSpan] = []
        current = sorted_spans[0]

        for nxt in sorted_spans[1:]:
            gap = nxt.start - current.end
            if (
                nxt.entity_type == current.entity_type
                and nxt.source == current.source
                and gap <= 2
            ):
                current = DetectedSpan(
                    start=current.start,
                    end=nxt.end,
                    text=current.text + (" " if gap > 0 else "") + nxt.text,
                    entity_type=current.entity_type,
                    confidence=max(current.confidence, nxt.confidence),
                    source=current.source,
                    is_regex_validated=current.is_regex_validated
                    or nxt.is_regex_validated,
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
    EntityType.IFSC,
    EntityType.UEN,
    EntityType.CRN,
}


class SpanConflictResolver:
    """
    Resolves conflicts between DetectedSpan objects from different NER layers.

    Conflict resolution priority rules (applied in order):
      0. If one span's range fully contains the other's, the containing
         (longer) span always wins outright — this stops a short
         sub-pattern from claiming a *fragment* of a longer, correctly-
         matched span (see V-16: a 7-digit sub-pattern used to grab the
         middle of a longer spaced phone number, leaving real digits
         outside the match in cleartext next to a marker that looked
         like the whole number had been handled).
      1. Regex-validated spans win over non-validated spans.
      2. Financial entity types override PHONE in overlapping spans.
      3. Higher confidence wins (when not regex-validated / financial).
      4. Longer span wins (when confidence is equal within 0.05).
      5. Duplicate entity (same start, end, entity_type) removed.

    After resolution, the output is a non-overlapping, deduplicated
    list of DetectedSpan objects, sorted by start offset.
    """

    def resolve(self, all_spans: list[DetectedSpan]) -> list[DetectedSpan]:
        """Merge spans from all NER layers into a single non-overlapping list."""
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
        """Choose between two overlapping spans."""
        if a.contains(b) and not b.contains(a):
            return a
        if b.contains(a) and not a.contains(b):
            return b

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
    Top-level NER engine composing regex, GLiNER, spaCy, and transformer
    privacy-filter detection layers.

    Usage
    -----
    ::

        engine = NEREngine()   # regex only, no extra dependencies
        spans = engine.detect("Invoice from Acme Corp, GST: 27AAPFU0939F1ZV")

        # with spaCy (requires pii-protect[spacy]):
        engine = NEREngine(enable_spacy=True)

        # with GLiNER (requires pii-protect[gliner]; weights must be
        # cached ahead of time — see pii_protect.ner.prefetch):
        engine = NEREngine(enable_gliner=True)
    """

    def __init__(
        self,
        enable_spacy: bool = False,
        spacy_model: str = "en_core_web_sm",
        enable_gliner: bool = False,
        gliner_model: str = "gliner-community/gliner_small-v2.5",
        gliner_threshold: float = 0.60,
        gliner_local_files_only: bool = True,
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
            the ``pii-protect[spacy]`` extra.
        spacy_model : str
            spaCy model name (must be installed).
        enable_gliner : bool
            Enable the GLiNER zero-shot layer. Requires the
            ``pii-protect[gliner]`` extra.
        gliner_model : str
            GLiNER model identifier.
        gliner_threshold : float
            Minimum GLiNER score for an entity span to be accepted.
        gliner_local_files_only : bool
            If True (default), GLiNER refuses to download weights at
            construction time — it raises immediately if they aren't
            already cached, instead of silently fetching them. Set to
            False only if you deliberately want on-demand downloading.
        enable_privacy_filter : bool
            Enable the transformer token-classification layer. Requires
            the ``pii-protect[privacy-filter]`` extra.
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

        self._gliner_layer: Optional[GLiNERLayer] = None
        if enable_gliner:
            self._gliner_layer = GLiNERLayer(
                model_name=gliner_model,
                threshold=gliner_threshold,
                local_files_only=gliner_local_files_only,
            )

        self._privacy_filter_layer: Optional[PrivacyFilterLayer] = None
        if enable_privacy_filter:
            if not privacy_filter_model:
                raise ValueError(
                    "privacy_filter_model is required when enable_privacy_filter=True"
                )
            self._privacy_filter_layer = PrivacyFilterLayer(
                privacy_filter_model, privacy_filter_threshold, privacy_filter_device
            )

        self._merger = TokenizerSafeSpanMerger()
        self._resolver = SpanConflictResolver()
        logger.info(
            "NEREngine ready (layers: regex, gliner=%s, spacy=%s, privacy_filter=%s)",
            gliner_model if enable_gliner else "DISABLED",
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

        Raises
        ------
        InvalidInputError
            If ``text`` is not a string (e.g. None, an int, a list) —
            raised here instead of letting an unrelated AttributeError
            leak out of ``text.strip()`` (see V-7).
        """
        if not isinstance(text, str):
            raise InvalidInputError(
                f"NEREngine.detect() expects a str, got {type(text).__name__}."
            )

        if not text.strip():
            return []

        regex_spans = self._regex_layer.detect(text)
        gliner_spans = self._gliner_layer.detect(text) if self._gliner_layer else []
        spacy_spans = self._spacy_layer.detect(text) if self._spacy_layer else []
        privacy_filter_spans = (
            self._privacy_filter_layer.detect(text)
            if self._privacy_filter_layer
            else []
        )

        all_spans = regex_spans + gliner_spans + spacy_spans + privacy_filter_spans
        resolved = self._resolver.resolve(all_spans)

        logger.debug(
            "NEREngine.detect: regex=%d gliner=%d spacy=%d privacy_filter=%d resolved=%d",
            len(regex_spans),
            len(gliner_spans),
            len(spacy_spans),
            len(privacy_filter_spans),
            len(resolved),
        )
        return resolved
