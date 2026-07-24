"""
pii_protect.tokens
===================
DeterministicTokenGenerator — produces placeholder tokens for masked PII.

Token format:  {{ENTITY_TYPE:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}}
Example:       {{EMAIL:3f9a2b7c1d8e4f6a0b2c9d7e1f4a8b3c}}

Design
------
  - 32-character hex suffix (128 bits) derived from
    SHA-256(plaintext | entity_type | scope | salt).
  - Deterministic: the same (plaintext, entity_type, scope) always
    produces the same suffix under one salt — this is what makes
    within-scope deduplication and unmask() lookups work.
  - Scope is part of the derivation (not just an afterthought on the
    storage record): the same PII value in two different scopes gets
    two different tokens. This is what makes scope a real isolation and
    deletion boundary rather than just a label — see
    PIIMaskingEngine.unmask()'s scope check and
    StorageBackend.delete_by_scope().
  - No sequential IDs — the suffix is hash-derived, not a counter, so it
    reveals nothing about insertion order or vault size.
  - Collision probability over 128 bits is astronomically small (this
    replaces an earlier 20-bit design that collided in practice after
    only ~1,200 values of one type — see PIIMaskingEngine._store_span's
    collision guard, which still checks and refuses to silently
    overwrite/leak a value on the vanishingly unlikely chance of a
    collision).
  - The salt MUST be supplied explicitly (constructor arg or the
    PII_PROTECT_SALT env var) — there is no hardcoded fallback. A shared
    default salt would make tokens predictable/guessable across every
    default install; failing closed here is intentional. Use
    ``DeterministicTokenGenerator.generate_salt()`` to create one.
  - Hashing normalises the plaintext to Unicode NFC first, so the same
    human-readable value in different Unicode normalisation forms
    (e.g. precomposed vs. combining-character accents — common across
    OSes/OCR pipelines) still deduplicates to the same token. The
    *encrypted* value stored in the vault is still the original,
    un-normalised text — normalisation only affects hashing/tokenising,
    never what's actually persisted or returned by unmask().

Author: Musaib Altaf
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import unicodedata
from typing import Optional

from pii_protect.types import EntityType

# 128-bit suffix (16 bytes -> 32 hex chars)
_SUFFIX_LEN_BYTES = 16
_SUFFIX_LEN_HEX = _SUFFIX_LEN_BYTES * 2

# Token regex for parsing masked text (used by PIIMaskingEngine.unmask)
TOKEN_PATTERN = re.compile(r"\{\{([A-Z_]+):([0-9a-f]{32})\}\}")

_SALT_ENV_VAR = "PII_PROTECT_SALT"


def _normalise(plaintext: str) -> str:
    """Canonicalise Unicode form before hashing (NFC) — see module docstring."""
    return unicodedata.normalize("NFC", plaintext)


class DeterministicTokenGenerator:
    """
    Generates deterministic, non-sequential, scope-bound placeholder
    tokens for PII masking.

    Each token encodes only the entity type (human-readable label) and a
    32-hex-character (128-bit) hash suffix, derived from:
        SHA-256(NFC(plaintext) + "|" + entity_type.value + "|" + (scope or "") + "|" + salt)

    Attributes
    ----------
    _salt : str
        Per-instance secret salt. Required — either passed explicitly or
        read from the ``PII_PROTECT_SALT`` env var. There is no insecure
        default; construction raises if neither is provided.
    """

    def __init__(self, salt: Optional[str] = None) -> None:
        resolved_salt = salt or os.environ.get(_SALT_ENV_VAR)
        if not resolved_salt:
            raise ValueError(
                "DeterministicTokenGenerator requires a salt — pass one explicitly, "
                f"or set the {_SALT_ENV_VAR} environment variable. A shared default "
                "salt would make every token predictable across installs, so there "
                "is no fallback. Generate one with "
                "DeterministicTokenGenerator.generate_salt() and store it alongside "
                "your encryption key."
            )
        self._salt = resolved_salt

    @staticmethod
    def generate_salt() -> str:
        """Generate a new random salt suitable for production use. Persist it — losing it changes every future token."""
        return secrets.token_hex(32)

    def generate(
        self, plaintext: str, entity_type: EntityType, scope: Optional[str] = None
    ) -> str:
        """
        Generate a deterministic token for a plaintext PII value within a scope.

        Parameters
        ----------
        plaintext : str
            The raw PII value (e.g. 'john.doe@acme.com').
        entity_type : EntityType
            The detected entity type (used in the token label).
        scope : Optional[str]
            The scope this value is being masked under. Bound into the
            token derivation so the same value produces different
            tokens in different scopes (isolation) — pass ``None`` for
            the unscoped/global namespace.

        Returns
        -------
        str
            Token string, e.g. '{{EMAIL:3f9a2b7c1d8e4f6a0b2c9d7e1f4a8b3c}}'.
        """
        suffix = self._derive_suffix(plaintext, entity_type, scope)
        return f"{{{{{entity_type.value}:{suffix}}}}}"

    def parse_token(self, token: str) -> Optional[tuple[EntityType, str]]:
        """
        Parse a token string back into its entity type and suffix.

        Parameters
        ----------
        token : str
            Token string, e.g. '{{EMAIL:3f9a2b7c1d8e4f6a0b2c9d7e1f4a8b3c}}'.

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
            Masked document text containing {{TYPE:xxxx...}} placeholders.

        Returns
        -------
        list[tuple[int, int, str]]
            List of (start, end, token_string) for each match.
        """
        return [(m.start(), m.end(), m.group()) for m in TOKEN_PATTERN.finditer(text)]

    def compute_value_hash(self, plaintext: str) -> str:
        """
        Compute the SHA-256 hash of a (NFC-normalised) plaintext value,
        used for within-scope deduplication.

        Computed WITHOUT the salt so storage backends can match across
        different service instances sharing one storage backend, and
        WITHOUT scope, since scope-scoping of the dedup index is handled
        by storage backends via the (value_hash, scope) composite key.

        Parameters
        ----------
        plaintext : str
            Raw PII value.

        Returns
        -------
        str
            64-character hex SHA-256 digest of the NFC-normalised value.
        """
        return hashlib.sha256(_normalise(plaintext).encode("utf-8")).hexdigest()

    # ── Internal ──────────────────────────────────────────────────────────

    def _derive_suffix(
        self, plaintext: str, entity_type: EntityType, scope: Optional[str]
    ) -> str:
        """
        Derive the 32-character (128-bit) hex suffix for a token.

        Formula: SHA-256(NFC(plaintext) + "|" + entity_type.value + "|" + (scope or "") + "|" + salt)
        Take the first 16 bytes of the digest, format as 32 lowercase hex chars.
        """
        payload = (
            f"{_normalise(plaintext)}|{entity_type.value}|{scope or ''}|{self._salt}"
        )
        digest = hashlib.sha256(payload.encode("utf-8")).digest()
        return digest[:_SUFFIX_LEN_BYTES].hex()
