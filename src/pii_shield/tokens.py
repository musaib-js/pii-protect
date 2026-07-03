"""
pii_shield.tokens
===================
DeterministicTokenGenerator — produces UUID-fragment placeholder tokens.

Token format:  {{ENTITY_TYPE:XXXXX}}
Example:       {{EMAIL:abcc2}}  {{PERSON:f38d4}}  {{GST:9a03b}}

Design:
  - 5-character hex suffix derived from SHA-256(value + entity_type + salt).
  - Deterministic: same value + entity_type -> same suffix within a session.
  - No sequential IDs — suffix is hash-derived, not a counter.
  - Collision probability over 5 hex chars (20 bits): ~1/1M per entity type.
    Acceptable for typical document volumes; storage-level deduplication
    (value_hash) handles the rest.
  - Salt is per-instance (set at construction, or from the PII_SHIELD_SALT
    env var). Different instances produce different tokens for the same
    value — the storage backend is the only source of truth.

Author: Musaib Altaf
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Optional

from pii_shield.types import EntityType

# Chars allowed in token suffix: lowercase hex only (URL-safe, no ambiguity)
_SUFFIX_CHARS = "0123456789abcdef"
_SUFFIX_LEN = 5

# Token regex for parsing masked text (used by PIIMaskingEngine.unmask)
TOKEN_PATTERN = re.compile(r"\{\{([A-Z_]+):([0-9a-f]{5})\}\}")


class DeterministicTokenGenerator:
    """
    Generates deterministic, non-sequential placeholder tokens for PII masking.

    Each token encodes only the entity type (human-readable label) and a
    5-hex-character hash suffix. The suffix is derived from:
        SHA-256(plaintext_value + "|" + entity_type.value + "|" + salt)

    This ensures:
    - Same plaintext in the same document -> same token (natural deduplication).
    - Different plaintext -> different token (with extremely high probability).
    - Tokens from one instance cannot be decoded without the storage backend.

    Attributes
    ----------
    _salt : str
        Per-instance secret salt. Defaults to the ``PII_SHIELD_SALT`` env
        var, or a hardcoded dev value if unset — always set explicitly in
        production.
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        self._salt = salt or os.environ.get("PII_SHIELD_SALT", "pii-shield-dev-salt-change-me")

    def generate(self, plaintext: str, entity_type: EntityType) -> str:
        """
        Generate a deterministic token for a plaintext PII value.

        Parameters
        ----------
        plaintext : str
            The raw PII value (e.g. 'john.doe@acme.com').
        entity_type : EntityType
            The detected entity type (used in the token label).

        Returns
        -------
        str
            Token string, e.g. '{{EMAIL:abcc2}}'.

        Examples
        --------
        >>> gen = DeterministicTokenGenerator(salt="test")
        >>> gen.generate("john.doe@acme.com", EntityType.EMAIL)
        '{{EMAIL:f38d4}}'
        """
        suffix = self._derive_suffix(plaintext, entity_type)
        return f"{{{{{entity_type.value}:{suffix}}}}}"

    def parse_token(self, token: str) -> Optional[tuple[EntityType, str]]:
        """
        Parse a token string back into its entity type and suffix.

        Parameters
        ----------
        token : str
            Token string, e.g. '{{EMAIL:abcc2}}'.

        Returns
        -------
        Optional[tuple[EntityType, str]]
            (entity_type, suffix) if the token is valid, else None.
        """
        match = TOKEN_PATTERN.fullmatch(token)
        if not match:
            return None
        label, suffix = match.group(1), match.group(2)
        try:
            return EntityType(label), suffix
        except ValueError:
            return None

    def find_tokens_in_text(self, text: str) -> list[tuple[int, int, str]]:
        """
        Find all token placeholders in a (masked) text.

        Parameters
        ----------
        text : str
            Masked document text containing {{TYPE:xxxxx}} placeholders.

        Returns
        -------
        list[tuple[int, int, str]]
            List of (start, end, token_string) for each match.
        """
        return [(m.start(), m.end(), m.group()) for m in TOKEN_PATTERN.finditer(text)]

    def compute_value_hash(self, plaintext: str) -> str:
        """
        Compute the SHA-256 hash of a plaintext value for deduplication.

        Computed WITHOUT the salt so storage backends can match across
        different service instances (important for multi-instance
        deployments sharing one storage backend).

        Parameters
        ----------
        plaintext : str
            Raw PII value.

        Returns
        -------
        str
            64-character hex SHA-256 digest.
        """
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    # ── Internal ──────────────────────────────────────────────────────────

    def _derive_suffix(self, plaintext: str, entity_type: EntityType) -> str:
        """
        Derive the 5-character hex suffix for a token.

        Formula: SHA-256(plaintext + "|" + entity_type.value + "|" + salt)
        Take the first 4 bytes of the digest, format as 5 lowercase hex chars.
        """
        payload = f"{plaintext}|{entity_type.value}|{self._salt}"
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        return digest[:4].hex()[:_SUFFIX_LEN]
