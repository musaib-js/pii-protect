"""
pii_protect.engine
====================
PIIMaskingEngine — the library's single public entry point.

Composes:
  - a NEREngine (detection: regex, optionally GLiNER / spaCy / transformer layers)
  - a DeterministicTokenGenerator (produces {{TYPE:xxxx...}} placeholders, scope-bound)
  - an AESGCMCipher (encrypts PII values before they reach storage)
  - a pluggable StorageBackend (in-memory, filesystem, Redis, or Postgres)

Core operations:
  - mask()   — reversible: detect PII, encrypt it, store it (scoped),
               replace it with a placeholder token. Reversed by unmask().
  - unmask() — reverses mask(): resolves placeholder tokens back to
               their original plaintext values via the storage backend,
               refusing to resolve a token outside the scope it was
               masked under.
  - redact() — irreversible: detect PII and replace it with a generic
               "[REDACTED:TYPE]" marker. Nothing is encrypted or stored.
  - delete_scope() — permanently deletes every vault record associated
               with a scope (e.g. when a customer/document is deleted).
  - rotate_encryption_key() — re-encrypts every stored value under a new
               key, for use if the current key is suspected compromised.
  - render_partial_mask() — a pure display-layer transform (no storage
               access) that shows part of each detected value (e.g. the
               last 6 digits of an account number) instead of a full
               token or full redaction. Layered on top of an existing
               MaskResult; does not change mask()/unmask() at all.

Author: Musaib Altaf
"""

from __future__ import annotations

import json
import logging
import re
from copy import deepcopy
from typing import Any, Optional, Union

from pii_protect.crypto import AESGCMCipher
from pii_protect.exceptions import (
    DecryptionError,
    EngineNotInitialisedError,
    InvalidInputError,
    TokenCollisionError,
)
from pii_protect.ner import NEREngine
from pii_protect.partial_mask import render_partial_mask as _render_partial_mask
from pii_protect.storage.base import StorageBackend
from pii_protect.tokens import DeterministicTokenGenerator
from pii_protect.types import (
    DetectedEntityInfo,
    EntityType,
    MaskResult,
    PartialMaskRule,
    TokenRecord,
    UnmaskResult,
)

logger = logging.getLogger(__name__)

_NUMBER_RE = re.compile(r"-?\d+(\.\d+)?")


class PIIMaskingEngine:
    """
    The main pii_protect entry point: reversible mask/unmask, irreversible
    redact, scope-based deletion, key rotation, and partial-mask
    rendering — all over a pluggable storage backend.

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
        Custom-configured NEREngine. Defaults to a regex-only NEREngine() if omitted.
    token_generator : Optional[DeterministicTokenGenerator]
        Custom token generator (e.g. with a specific salt). Defaults to a
        new DeterministicTokenGenerator() if omitted — which itself
        requires an explicit salt or the pii_protect_SALT env var to be set.
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
        actor: str = "pii_protect",
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
        the storage backend under ``scope``, and replace it with a
        ``{{TYPE:xxxx...}}`` placeholder token.

        Parameters
        ----------
        text : str
            Plain text to scan and mask.
        scope : Optional[str]
            Scoping identifier (e.g. a document/customer/invoice ID).
            Every stored record is tagged with this scope — pass ``None``
            for the unscoped/global namespace. The same value masked
            under two different scopes gets two different tokens (scope
            is an isolation boundary, not just a label): pass the same
            scope to the matching unmask() call, and use
            ``delete_scope()`` to purge everything under one scope at once.

        Returns
        -------
        MaskResult
            masked_text, token_count, entity_counts, and per-entity detail.

        Raises
        ------
        InvalidInputError
            If ``text`` is not a string.
        """
        self._assert_initialised()
        self._assert_str(text, "text")

        spans = self._ner.detect(text)
        if not spans:
            return MaskResult(masked_text=text, token_count=0, entity_counts={})

        entities: list[DetectedEntityInfo] = []
        entity_counts: dict[str, int] = {}

        result_text = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            token_value = await self._store_span(span.text, span.entity_type, scope)
            result_text = (
                result_text[: span.start] + token_value + result_text[span.end :]
            )

            entities.append(
                DetectedEntityInfo(
                    entity_type=span.entity_type.value,
                    start=span.start,
                    end=span.end,
                    token=token_value,
                    confidence=span.confidence,
                    source=span.source,
                )
            )
            entity_counts[span.entity_type.value] = (
                entity_counts.get(span.entity_type.value, 0) + 1
            )

        entities.reverse()  # restore left-to-right order (we iterated right-to-left)
        return MaskResult(
            masked_text=result_text,
            token_count=len(entities),
            entity_counts=entity_counts,
            entities=entities,
        )

    async def mask_dict(self, data: dict, scope: Optional[str] = None) -> dict:
        """
        Deep-mask a JSON-serialisable dict/list structure by masking
        every string (and PII-bearing numeric) leaf value.

        Walks the structure directly rather than serialising the whole
        thing to one JSON string and masking that blob: a numeric leaf
        containing PII digits (e.g. ``{"phone": 9876543210}``) can't be
        safely token-substituted inside an unquoted JSON number without
        producing invalid JSON, which used to crash the whole call.
        Instead, each leaf is masked independently; a numeric leaf is
        only converted to a string if PII was actually found in it,
        otherwise its original type is preserved untouched.

        Repeated values across different leaves still deduplicate to the
        same token, since every leaf goes through the same storage
        backend's scope-aware dedup index.
        """
        self._assert_initialised()
        return await self._mask_walk(deepcopy(data), scope)

    async def mask_dict_with_known_pii_keys(
        self,
        data: dict,
        pii_keys: list[str],
        scope: Optional[str] = None,
    ) -> dict:
        """
        Recursively traverse a dict/list structure and mask the values of
        keys present in ``pii_keys``, at any depth.

        Unlike ``mask()``/``mask_dict()``, this does not run NER
        detection — it masks the *entire* value of any matching key,
        trusting the caller's declaration of which keys hold PII. Useful
        when you already know your schema (e.g. ``["ssn", "account_number"]``)
        and want a value masked in full regardless of whether it happens
        to match a detection pattern.
        """
        self._assert_initialised()
        pii_key_set = set(pii_keys)

        async def _walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                result = {}
                for key, value in obj.items():
                    if key in pii_key_set:
                        if value is None:
                            result[key] = None
                        else:
                            plaintext = (
                                value
                                if isinstance(value, str)
                                else (
                                    json.dumps(value, default=str)
                                    if isinstance(value, (dict, list))
                                    else str(value)
                                )
                            )
                            result[key] = await self._store_span(
                                plaintext, EntityType.CUSTOM, scope
                            )
                    else:
                        result[key] = await _walk(value)
                return result
            if isinstance(obj, list):
                return [await _walk(item) for item in obj]
            return obj

        return await _walk(deepcopy(data))

    # ── Unmask (reverses mask) ───────────────────────────────────────────

    async def unmask(
        self,
        masked_text: str,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> str:
        """
        Replace all ``{{TYPE:xxxx...}}`` tokens in ``masked_text`` with
        their original decrypted values.

        Parameters
        ----------
        masked_text : str
            Text previously produced by mask(), containing placeholder tokens.
        scope : Optional[str]
            The scope this text was masked under. A token whose stored
            scope doesn't match is refused (left as
            ``[SCOPE_DENIED]``) rather than resolved — scope is an
            isolation boundary, not just an audit label, so a token
            minted under one scope cannot be read back under another.
        actor : Optional[str]
            Overrides the engine's default actor identity for this call.

        Returns
        -------
        str
            Text with all resolvable tokens replaced by original values.
            - Tokens not found in storage are left as ``[UNRESOLVED]``.
            - Tokens found but whose scope doesn't match are left as
              ``[SCOPE_DENIED]``.
            - Tokens found but that fail to decrypt (tampering, or a
              corrupted/mismatched record) are left as ``[TAMPERED]``.
            A problem with one token never aborts resolution of the
            others in the same call.
        """
        result = await self._unmask_with_stats(masked_text, scope, actor)
        return result.text

    async def unmask_with_stats(
        self,
        masked_text: str,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> UnmaskResult:
        """Same as unmask(), but also returns resolved/unresolved/denied/tampered token counts."""
        return await self._unmask_with_stats(masked_text, scope, actor)

    async def unmask_dict(
        self,
        data: dict,
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> dict:
        """Deep-unmask a JSON-serialisable dict/list structure previously produced by mask_dict()."""
        self._assert_initialised()
        return await self._unmask_walk(deepcopy(data), scope, actor)

    async def unmask_dict_with_known_pii_keys(
        self,
        data: dict,
        pii_keys: list[str],
        scope: Optional[str] = None,
        actor: Optional[str] = None,
    ) -> dict:
        """Reverse mask_dict_with_known_pii_keys() by unmasking the values of the specified keys."""
        self._assert_initialised()
        pii_key_set = set(pii_keys)

        async def _walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                result = {}
                for key, value in obj.items():
                    if key in pii_key_set:
                        if value is None:
                            result[key] = None
                        elif isinstance(value, str):
                            result[key] = await self.unmask(
                                value, scope=scope, actor=actor
                            )
                        else:
                            result[key] = value
                    else:
                        result[key] = await _walk(value)
                return result
            if isinstance(obj, list):
                return [await _walk(item) for item in obj]
            return obj

        return await _walk(deepcopy(data))

    # ── Redact (irreversible) ────────────────────────────────────────────

    def redact(self, text: str) -> str:
        """
        Detect PII in ``text`` and replace each occurrence with a generic
        ``[REDACTED:TYPE]`` marker.

        Irreversible by design: nothing is encrypted, nothing is written
        to the storage backend, and no token can later be resolved back
        to the original value.

        Raises
        ------
        InvalidInputError
            If ``text`` is not a string.
        """
        self._assert_str(text, "text")
        spans = self._ner.detect(text)
        if not spans:
            return text

        result_text = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            marker = f"[REDACTED:{span.entity_type.value}]"
            result_text = result_text[: span.start] + marker + result_text[span.end :]
        return result_text

    # ── Partial masking (display-only, no storage involved) ──────────────

    def render_partial_mask(
        self,
        original_text: str,
        result: MaskResult,
        rules: dict[Union[str, EntityType], PartialMaskRule],
        default_mask_char: str = "*",
    ) -> str:
        """
        Render a partially-masked version of ``original_text`` — showing
        a configurable slice of each detected value (e.g. the last 6
        digits of an account number) instead of a full token or full
        redaction.

        This is a pure function over data you already have: it does not
        call the storage backend, the cipher, or the token generator, and
        does not change what mask()/unmask() do at all. Call mask() as
        usual to get the reversible token flow; call this separately,
        with the *original* text and that call's MaskResult, whenever you
        need a customer-facing partially-visible rendering instead.

        Parameters
        ----------
        original_text : str
            The ORIGINAL text passed to mask() (not masked_text).
        result : MaskResult
            The MaskResult returned by the corresponding mask() call.
        rules : dict[str | EntityType, PartialMaskRule]
            Per-entity-type visibility rules, e.g.
            ``{"ACCOUNT": PartialMaskRule(visible_chars=6, position="end")}``.
            Entity types without a rule are fully masked.
        default_mask_char : str
            Mask character for entity types with no configured rule.

        Returns
        -------
        str
            A partially-masked rendering of ``original_text``.
        """
        return _render_partial_mask(
            original_text, result.entities, rules, default_mask_char
        )

    # ── Scope deletion ────────────────────────────────────────────────────

    async def delete_scope(self, scope: Optional[str]) -> int:
        """
        Permanently delete every vault record associated with ``scope``
        (e.g. when a customer, document, or invoice is deleted and its
        PII must be purged). This does not touch masked text you may
        still have lying around elsewhere — any tokens in it simply
        become unresolvable after this call.

        Parameters
        ----------
        scope : Optional[str]
            The scope to purge. Pass ``None`` to delete every record
            stored under the unscoped/global namespace.

        Returns
        -------
        int
            Number of records deleted.
        """
        self._assert_initialised()
        return await self._storage.delete_by_scope(scope)

    # ── Key rotation ──────────────────────────────────────────────────────

    async def rotate_encryption_key(self, new_key: "bytes | str") -> int:
        """
        Re-encrypt every record currently in the storage backend with a
        new AES-256 key, then switch the engine to use it. Use this if
        the current key is suspected to be compromised.

        This is a two-phase rotation: every record is first decrypted
        under the CURRENT key and held in memory — nothing is written in
        this phase. Only if every record decrypts successfully does the
        engine proceed to re-encrypt each value with the new key and
        persist it. If any record fails to decrypt (tampering, or an
        already-corrupted record), the whole rotation aborts before any
        record is modified, and the engine keeps using the current key —
        so a partial/half-rotated vault is not a possible outcome.

        Note: this holds every plaintext value in memory for the duration
        of the rotation (needed to validate before writing anything). For
        very large vaults, consider a maintenance-window rotation.

        Parameters
        ----------
        new_key : bytes | str
            A fresh 32-byte AES-256 key, or a 64-character hex string.
            Generate one with ``AESGCMCipher.generate_key()``.

        Returns
        -------
        int
            Number of records re-encrypted.

        Raises
        ------
        DecryptionError
            If any existing record fails to decrypt under the current
            key. No records are modified in this case.
        """
        self._assert_initialised()
        new_cipher = (
            AESGCMCipher.from_hex(new_key)
            if isinstance(new_key, str)
            else AESGCMCipher(new_key)
        )

        # Phase 1: decrypt + validate everything under the CURRENT key.
        # Nothing is written to storage in this phase.
        decrypted: list[tuple[TokenRecord, str]] = []
        async for record in self._storage.all_records():
            aad = record.entity_type.encode("utf-8")
            plaintext = self._cipher.decrypt(
                record.ciphertext, record.iv, record.tag, aad
            )
            decrypted.append((record, plaintext))

        # Phase 2: re-encrypt everything with the new key and persist.
        rotated_count = 0
        for record, plaintext in decrypted:
            aad = record.entity_type.encode("utf-8")
            ct = new_cipher.encrypt(plaintext, aad)
            await self._storage.replace_ciphertext(
                record.token_value, ct.ciphertext, ct.iv, ct.tag
            )
            rotated_count += 1

        del decrypted  # best-effort: drop plaintext references promptly
        self._cipher = new_cipher
        logger.info("Key rotation complete: %d record(s) re-encrypted.", rotated_count)
        return rotated_count

    # ── Internal ──────────────────────────────────────────────────────────

    async def _store_span(
        self, plaintext: str, entity_type: Any, scope: Optional[str]
    ) -> str:
        """
        Encrypt and persist one detected span, deduplicating within scope.

        Guards against token collisions (two different plaintext values
        hashing to the same token): with a 128-bit token suffix this
        should never happen in practice, but if it ever does, we refuse
        to silently overwrite/leak the existing value.
        """
        value_hash = self._token_gen.compute_value_hash(plaintext)

        existing_token = await self._storage.find_by_value_hash(value_hash, scope)
        if existing_token:
            await self._storage.touch(existing_token)
            await self._storage.log_access(existing_token, "MASK", self._actor, scope)
            return existing_token

        token_value = self._token_gen.generate(plaintext, entity_type, scope)

        existing_record = await self._storage.get(token_value)
        if existing_record is not None:
            if existing_record.value_hash != value_hash:
                raise TokenCollisionError(
                    f"Token collision detected for {token_value!r}: an existing record's "
                    "value_hash doesn't match the new value's hash. Refusing to store, "
                    "to avoid silently corrupting/leaking the existing value."
                )
            # Same (plaintext, entity_type, scope) re-derived — safe to reuse.
            await self._storage.touch(token_value)
            await self._storage.log_access(token_value, "MASK", self._actor, scope)
            return token_value

        aad = entity_type.value.encode("utf-8")
        ct = self._cipher.encrypt(plaintext, aad)

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
        self._assert_str(masked_text, "masked_text")

        token_positions = self._token_gen.find_tokens_in_text(masked_text)
        if not token_positions:
            return UnmaskResult(text=masked_text, tokens_resolved=0)

        unique_tokens = list({t for _, _, t in token_positions})
        records = await self._storage.get_many(unique_tokens)

        resolved: dict[str, str] = {}
        denied: set[str] = set()
        tampered: set[str] = set()

        for token_value, record in records.items():
            if record.scope != scope:
                denied.add(token_value)
                continue

            aad = record.entity_type.encode("utf-8")
            try:
                resolved[token_value] = self._cipher.decrypt(
                    record.ciphertext, record.iv, record.tag, aad
                )
            except DecryptionError:
                # A single tampered/corrupted record must not abort the whole batch.
                tampered.add(token_value)
                logger.warning(
                    "Token %s failed decryption (tampered or corrupted record); leaving unresolved.",
                    token_value,
                )
                continue

            await self._storage.touch(token_value)
            await self._storage.log_access(
                token_value, "UNMASK", actor or self._actor, scope
            )

        result_text = masked_text
        unresolved_count = 0
        denied_count = 0
        tampered_count = 0

        for start, end, token in reversed(token_positions):
            if token in resolved:
                result_text = result_text[:start] + resolved[token] + result_text[end:]
            elif token in denied:
                denied_count += 1
                result_text = (
                    result_text[:start] + f"{token}[SCOPE_DENIED]" + result_text[end:]
                )
            elif token in tampered:
                tampered_count += 1
                result_text = (
                    result_text[:start] + f"{token}[TAMPERED]" + result_text[end:]
                )
            else:
                unresolved_count += 1
                result_text = (
                    result_text[:start] + f"{token}[UNRESOLVED]" + result_text[end:]
                )

        return UnmaskResult(
            text=result_text,
            tokens_resolved=len(resolved),
            tokens_unresolved=unresolved_count,
            tokens_denied=denied_count,
            tokens_tampered=tampered_count,
        )

    async def _mask_walk(self, obj: Any, scope: Optional[str]) -> Any:
        if isinstance(obj, dict):
            return {k: await self._mask_walk(v, scope) for k, v in obj.items()}
        if isinstance(obj, list):
            return [await self._mask_walk(item, scope) for item in obj]
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, str):
            result = await self.mask(obj, scope=scope)
            return result.masked_text
        if isinstance(obj, (int, float)):
            # PII can show up as a bare number (e.g. a phone field stored as an int).
            # Detect against the stringified form; only convert the leaf to a string
            # if something was actually masked, otherwise keep the original type.
            as_text = str(obj)
            result = await self.mask(as_text, scope=scope)
            return result.masked_text if result.token_count else obj
        return obj

    async def _unmask_walk(
        self, obj: Any, scope: Optional[str], actor: Optional[str]
    ) -> Any:
        if isinstance(obj, dict):
            return {k: await self._unmask_walk(v, scope, actor) for k, v in obj.items()}
        if isinstance(obj, list):
            return [await self._unmask_walk(item, scope, actor) for item in obj]
        if isinstance(obj, str):
            unmasked = await self.unmask(obj, scope=scope, actor=actor)
            return self._maybe_coerce_number(unmasked) if unmasked != obj else obj
        return obj

    @staticmethod
    def _maybe_coerce_number(s: str) -> Any:
        """Best-effort: restore a leaf to int/float if unmasking fully resolved it back to a bare number."""
        if _NUMBER_RE.fullmatch(s):
            try:
                return int(s) if "." not in s else float(s)
            except ValueError:
                pass
        return s

    def _assert_initialised(self) -> None:
        if not self._initialised:
            raise EngineNotInitialisedError(
                "PIIMaskingEngine.initialise() must be called before use "
                "(or use 'async with PIIMaskingEngine(...) as engine:')."
            )

    @staticmethod
    def _assert_str(value: Any, param_name: str) -> None:
        if not isinstance(value, str):
            raise InvalidInputError(
                f"{param_name!r} must be a str, got {type(value).__name__}."
            )
