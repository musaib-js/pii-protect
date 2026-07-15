"""
pii_shield.types
==================
Shared data types used across the detection, masking, and storage layers.

Author: Musaib Altaf
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  Entity type enum (canonical across all detection layers)
# ─────────────────────────────────────────────────────────────────────────────

class EntityType(str, Enum):
    """Canonical PII entity categories detected and masked by pii_shield."""

    PERSON          = "PERSON"
    ORGANISATION    = "ORGANISATION"
    ADDRESS         = "ADDRESS"
    EMAIL           = "EMAIL"
    PHONE           = "PHONE"
    ACCOUNT         = "ACCOUNT"
    IBAN            = "IBAN"
    SWIFT           = "SWIFT"
    TAX_ID          = "TAX_ID"
    GST             = "GST"
    PAN             = "PAN"
    TAN             = "TAN"
    ABN             = "ABN"
    VAT             = "VAT"
    INVOICE_NUMBER  = "INVOICE_NUMBER"
    PO_NUMBER       = "PO_NUMBER"
    BANK_ACCOUNT    = "BANK_ACCOUNT"
    SORT_CODE       = "SORT_CODE"
    ROUTING_NUMBER  = "ROUTING_NUMBER"
    CREDIT_CARD     = "CREDIT_CARD"
    VENDOR_CODE     = "VENDOR_CODE"
    EMPLOYEE_ID     = "EMPLOYEE_ID"
    OTHER           = "OTHER"
    UPI             = "UPI"
    URL             = "URL"
    CUSTOM = "CUSTOM"
    


# ─────────────────────────────────────────────────────────────────────────────
#  Detection span (common output of all NER layers)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(order=True)
class DetectedSpan:
    """A detected PII entity span in the input text."""

    start: int                        # character offset (inclusive)
    end: int                          # character offset (exclusive)
    text: str                         # matched surface form
    entity_type: EntityType
    confidence: float                 # [0, 1]
    source: str                       # 'regex' | 'spacy' | 'privacy_filter'
    is_regex_validated: bool = False  # True if a regex pattern fully validated this span

    def overlaps(self, other: "DetectedSpan") -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: "DetectedSpan") -> bool:
        return self.start <= other.start and self.end >= other.end

    @property
    def length(self) -> int:
        return self.end - self.start


# ─────────────────────────────────────────────────────────────────────────────
#  Vault record  (persisted by storage backends)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TokenRecord:
    """
    A single encrypted PII value as persisted by a storage backend.

    ``scope`` is a free-form identifier (e.g. an invoice ID, a document ID,
    a tenant ID) used to namespace deduplication. Pass ``None`` for a
    global/unscoped vault.
    """

    token_value: str
    entity_type: str
    ciphertext: bytes
    iv: bytes
    tag: bytes
    original_length: int
    value_hash: str
    scope: Optional[str] = None
    access_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ─────────────────────────────────────────────────────────────────────────────
#  Mask/unmask results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DetectedEntityInfo:
    """Summary of a single detected entity span (for audit/debug)."""

    entity_type: str
    start: int
    end: int
    token: str      # the placeholder that replaced this span
    confidence: float
    source: str      # 'regex' | 'spacy' | 'privacy_filter'


@dataclass
class MaskResult:
    """Return value of ``PIIMaskingEngine.mask()``."""

    masked_text: str
    token_count: int
    entity_counts: dict[str, int]
    entities: list[DetectedEntityInfo] = field(default_factory=list)


@dataclass
class UnmaskResult:
    """Return value of ``PIIMaskingEngine.unmask()``."""

    text: str
    tokens_resolved: int
    tokens_unresolved: int = 0
