"""
pii_shield.engine
====================
PIIMaskingEngine — the library's single public entry point.

Composes:
  - a NEREngine (detection: regex, optionally spaCy / transformer layers)
  - a DeterministicTokenGenerator (produces {{TYPE:xxxxx}} placeholders)
  - an AESGCMCipher (encrypts PII values before they reach storage)
  - a pluggable StorageBackend (in-memory, filesystem, Redis, or Postgres)

Three operations are exposed:
  - mask()   — reversible: detect PII, encrypt it, store it, replace it
               with a placeholder token. Can be reversed with unmask().
  - unmask() — reverses mask(): resolves placeholder tokens back to
               their original plaintext values via the storage backend.
  - redact() — irreversible: detect PII and replace it with a generic
               "[REDACTED:TYPE]" marker. Nothing is encrypted or stored;
               there is no way to recover the original values.

Author: Musaib Altaf
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from pii_shield.crypto import AESGCMCipher
from pii_shield.exceptions import EngineNotInitialisedError
from pii_shield.ner import NEREngine
from pii_shield.storage.base import StorageBackend
from pii_shield.tokens import DeterministicTokenGenerator
from pii_shield.types import DetectedEntityInfo, MaskResult, UnmaskResult

logger = logging.getLogger(__name__)


class PIIMaskingEngine:
    """
    The main pii_shield entry point: reversible mask/unmask plus
    irreversible redact, over a pluggable storage backend.

    Usage
    -----
    ::

        from pii_shield import PIIMaskingEngine
        from pii_shield.storage import InMemoryStorage

        async with PIIMaskingEngine(storage=InMemoryStorage()) as engine:
            result = await engine.mask("Contact john@acme.com about GST 27AAPFU0939F1ZV")
            print(result.masked_text)   # "Contact {{EMAIL:abcc2}} about GST {{GST:9a03b}}"

            original = await engine.unmask(result.masked_text)
            print(original)             # "Contact john@acme.com about GST 27AAPFU0939F1ZV"

            print(engine.redact("Contact john@acme.com"))
            # "Contact [REDACTED:EMAIL]"  — irreversible, nothing stored

    Parameters
    ----------
    storage : StorageBackend
        Any StorageBackend implementation (InMemoryStorage,
        FileSystemStorage, RedisStorage, PostgresStorage, or a custom one).
    encryption_key : Optional[bytes | str]
        32-byte AES-256 key, or a 64-character hex string. If omitted, an
        ephemeral key is generated and a warning is logged — data masked
        with an ephemeral key becomes permanently unrecoverable once the
        process exits. Always set this explicitly outside of quick tests.
    ner_engine : Optional[NEREngine]
        Custom-configured NEREngine (e.g. with spaCy/privacy-filter layers
        enabled). Defaults to a regex-only NEREngine() if omitted.
    token_generator : Optional[DeterministicTokenGenerator]
        Custom token generator (e.g. with a specific salt). Defaults to a
        new DeterministicTokenGenerator() if omitted.
    actor : str
        Default identity recorded on storage backends that support audit
        logging (e.g. PostgresStorage.log_access). Overridable per call.
    """

    def __init__(
        self,
        storage: StorageBackend,
        encryption_key: Optional["bytes | str"] = None,
        ner_engine: Optional[NEREngine] = None,
        token_generator: Optional[DeterministicTokenGenerator] = None,
        actor: str = "pii_shield",
    ) -> None:
        self._storage = storage
        self._ner = ner_engine or NEREngine()
        self._token_gen = token_generator or DeterministicTokenGenerator()
        self._actor = actor

        if encryption_key is None:
            logger.warning(
                "PIIMaskingEngine: no encryption_key provided — generating an ephemeral "
                "key. Data masked in this session will be UNRECOVERABLE after the "
                "process exits. Pass a stable 32-byte key (or 64-char hex string) in "
                "production."
            )
            self._cipher = AESGCMCipher(AESGCMCipher.generate_key())
        elif isinstance(encryption_key, str):
            self._cipher = AESGCMCipher.from_hex(encryption_key)
        else:
            self._cipher = AESGCMCipher(encryption_key)

        self._initialised = False

    async def initialise(self) -> None:
        """Connect the storage backend. Must be called once before mask()/unmask()."""
        await self._storage.connect()
        self._initialised = True

    async def close(self) -> None:
        """Release storage backend resources."""
        await self._storage.close()
        self._initialised = False

    async def __aenter__(self) -> "PIIMaskingEngine":
        await self.initialise()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # ── Mask (reversible) ────────────────────────────────────────────────

    async def mask(self, text: str, scope: Optional[str] = None) -> MaskResult:
        """
        Detect PII in ``text``, encrypt each detected value, persist it to
        the storage backend, and replace it with a ``{{TYPE:xxxxx}}``
        placeholder token.

        Parameters
        ----------
        text : str
            Plain text to scan and mask.
        scope : Optional[str]
            Free-form scoping identifier (e.g. a document/invoice ID) used
            to namespace within-document deduplication. Pass the same
            scope on the matching unmask() call.

        Returns
        -------
        MaskResult
            masked_text, token_count, entity_counts, and per-entity detail.
        """
        self._assert_initialised()
        spans = self._ner.detect(text)
        if not spans:
            return MaskResult(masked_text=text, token_count=0, entity_counts={})

        entities: list[DetectedEntityInfo] = []
        entity_counts: dict[str, int] = {}

        result_text = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            token_value = await self._store_span(span.text, span.entity_type, scope)
            result_text = result_text[: span.start] + token_value + result_text[span.end :]

            entities.append(DetectedEntityInfo(
                entity_type=span.entity_type.value,
                start=span.start,
                end=span.end,
                token=token_value,
                confidence=span.confidence,
                source=span.source,
            ))
            entity_counts[span.entity_type.value] = entity_counts.get(span.entity_type.value, 0) + 1

        entities.reverse()  # restore left-to-right order (we iterated right-to-left)
        return MaskResult(
            masked_text=result_text,
            token_count=len(entities),
            entity_counts=entity_counts,
            entities=entities,
        )

    async def mask_dict(self, data: dict, scope: Optional[str] = None) -> dict:
        """
        Deep-mask a JSON-serialisable dict by masking all string leaf values.

        Serialises to JSON, masks the full JSON string in one pass (so
        repeated values across fields deduplicate to the same token), then
        deserialises.
        """
        self._assert_initialised()
        json_str = json.dumps(data, default=str)
        result = await self.mask(json_str, scope=scope)
        return json.loads(result.masked_text)

    # ── Unmask (reverses mask) ───────────────────────────────────────────

    async def unmask(
        self,
        masked_text: str,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> str:
        """
        Replace all ``{{TYPE:xxxxx}}`` tokens in ``masked_text`` with their
        original decrypted values.

        Parameters
        ----------
        masked_text : str
            Text previously produced by mask(), containing placeholder tokens.
        scope : Optional[str]
            Scoping identifier, passed through to the audit log if the
            backend supports one.
        actor : Optional[str]
            Overrides the engine's default actor identity for this call.

        Returns
        -------
        str
            Text with all resolvable tokens replaced by original values.
            Unresolvable tokens (not found in storage) are left in place
            with a ``[UNRESOLVED]`` suffix.
        """
        result = await self._unmask_with_stats(masked_text, scope, actor)
        return result.text

    async def unmask_with_stats(
        self,
        masked_text: str,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> UnmaskResult:
        """Same as unmask(), but also returns resolved/unresolved token counts."""
        return await self._unmask_with_stats(masked_text, scope, actor)

    async def unmask_dict(
        self,
        data: dict,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> dict:
        """Deep-unmask a JSON-serialisable dict previously produced by mask_dict()."""
        self._assert_initialised()
        json_str = json.dumps(data, default=str)
        unmasked = await self.unmask(json_str, scope=scope, actor=actor)
        return json.loads(unmasked)

    # ── Redact (irreversible) ────────────────────────────────────────────

    def redact(self, text: str) -> str:
        """
        Detect PII in ``text`` and replace each occurrence with a generic
        ``[REDACTED:TYPE]`` marker.

        This is irreversible by design: nothing is encrypted, nothing is
        written to the storage backend, and no token can later be resolved
        back to the original value. Use this when you need to permanently
        scrub PII (e.g. for logs, analytics exports, or third-party
        sharing) rather than mask() + unmask()'s reversible workflow.

        Parameters
        ----------
        text : str
            Plain text to scan and redact.

        Returns
        -------
        str
            Text with all detected PII spans replaced by
            ``[REDACTED:ENTITY_TYPE]`` markers.
        """
        spans = self._ner.detect(text)
        if not spans:
            return text

        result_text = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            marker = f"[REDACTED:{span.entity_type.value}]"
            result_text = result_text[: span.start] + marker + result_text[span.end :]
        return result_text

    # ── Internal ──────────────────────────────────────────────────────────

    async def _store_span(self, plaintext: str, entity_type: Any, scope: Optional[str]) -> str:
        """Encrypt and persist one detected span, deduplicating within scope."""
        value_hash = self._token_gen.compute_value_hash(plaintext)

        existing = await self._storage.find_by_value_hash(value_hash, scope)
        if existing:
            await self._storage.touch(existing)
            await self._storage.log_access(existing, "MASK", self._actor, scope)
            return existing

        token_value = self._token_gen.generate(plaintext, entity_type)
        aad = entity_type.value.encode("utf-8")
        ct = self._cipher.encrypt(plaintext, aad)

        from pii_shield.types import TokenRecord

        record = TokenRecord(
            token_value=token_value,
            entity_type=entity_type.value,
            ciphertext=ct.ciphertext,
            iv=ct.iv,
            tag=ct.tag,
            original_length=len(plaintext.encode("utf-8")),
            value_hash=value_hash,
            scope=scope,
        )
        await self._storage.put(record)
        await self._storage.log_access(token_value, "MASK", self._actor, scope)
        return token_value

    async def _unmask_with_stats(
        self, masked_text: str, scope: Optional[str], actor: Optional[str]
    ) -> UnmaskResult:
        self._assert_initialised()
        token_positions = self._token_gen.find_tokens_in_text(masked_text)
        if not token_positions:
            return UnmaskResult(text=masked_text, tokens_resolved=0, tokens_unresolved=0)

        unique_tokens = list({t for _, _, t in token_positions})
        records = await self._storage.get_many(unique_tokens)

        resolved: dict[str, str] = {}
        for token_value, record in records.items():
            aad = record.entity_type.encode("utf-8")
            resolved[token_value] = self._cipher.decrypt(record.ciphertext, record.iv, record.tag, aad)
            await self._storage.touch(token_value)
            await self._storage.log_access(token_value, "UNMASK", actor or self._actor, scope)

        result_text = masked_text
        unresolved_count = 0
        for start, end, token in reversed(token_positions):
            if token in resolved:
                result_text = result_text[:start] + resolved[token] + result_text[end:]
            else:
                unresolved_count += 1
                result_text = result_text[:start] + f"{token}[UNRESOLVED]" + result_text[end:]

        return UnmaskResult(
            text=result_text,
            tokens_resolved=len(token_positions) - unresolved_count,
            tokens_unresolved=unresolved_count,
        )

    def _assert_initialised(self) -> None:
        if not self._initialised:
            raise EngineNotInitialisedError(
                "PIIMaskingEngine.initialise() must be called before use "
                "(or use 'async with PIIMaskingEngine(...) as engine:')."
            )
