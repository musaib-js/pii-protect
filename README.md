# pii-protect

A pluggable, on-premise-first PII masking, unmasking, and redaction library for Python.

`pii-protect` detects personally identifiable and sensitive business
information in free text (emails, phone numbers, GST/PAN/IBAN/IFSC/UPI
numbers, person and organisation names, bank details, invoice/PO
references, and more), and gives you several ways to handle it:

- **mask** it into a reversible placeholder token, encrypted at rest, scoped
- **unmask** a previously masked token back to its original value
- **redact** it permanently, with no way to recover the original
- **partially mask** it for display — show a slice of the value, hide the rest
- **delete** every value tied to a scope (customer, document, tenant) in one call
- **rotate** the encryption key across the whole vault if it's ever compromised

There is no server, no API, and no hard dependency on any particular
database — it's a library you import and call directly. Where your
encrypted PII values live is a pluggable choice: in-memory, a local file,
Redis, or PostgreSQL, or a backend you write yourself.

---

## Install

```bash
pip install pii-protect                      # core: regex detection + in-memory/filesystem storage
pip install "pii-protect[postgres]"           # + PostgreSQL storage backend
pip install "pii-protect[redis]"              # + Redis storage backend
pip install "pii-protect[spacy]"              # + spaCy NER layer (PERSON/ORG/GPE)
pip install "pii-protect[gliner]"             # + GLiNER zero-shot NER layer
pip install "pii-protect[privacy-filter]"     # + transformer token-classification layer
pip install "pii-protect[all]"                # everything
```

Only `cryptography` is a hard dependency. `asyncpg`, `redis`, `spacy`,
`gliner`, and `transformers`/`torch` are all opt-in extras. If you use a
backend or detection layer without installing its extra, you get a clear
`OptionalDependencyMissingError` telling you exactly what to install —
never a bare `ImportError` or a silent failure.

`GLiNERLayer` and `PrivacyFilterLayer` also never download model weights
on their own — see [Configuring detection](#configuring-detection) for
how to warm their cache ahead of time.

---

## Required setup: encryption key and salt

Two secrets need to exist before you construct an engine. Neither has an
insecure default — both fail closed if you don't provide them, on purpose.

```python
from pii_protect.crypto import AESGCMCipher
from pii_protect.tokens import DeterministicTokenGenerator

encryption_key = AESGCMCipher.generate_key()          # 32 bytes — persist this
salt = DeterministicTokenGenerator.generate_salt()    # persist this too
```

- **`encryption_key`** — a 32-byte AES-256 key (or a 64-character hex
  string). Lose it and every previously masked value becomes permanently
  unrecoverable. If you omit it, the engine generates an ephemeral one
  and logs a warning — fine for a quick script, never for production.
- **`salt`** — required by `DeterministicTokenGenerator`, either passed
  explicitly or read from the `pii_protect_SALT` environment variable.
  There's no hardcoded fallback: a shared default salt would make every
  token predictable across every default install of the library, so
  construction raises `ValueError` instead of silently using one.

Store both the same way you'd store any other production secret (a
secrets manager, environment variables injected at deploy time, etc.).

---

## Quick start

```python
import asyncio
from pii_protect import PIIMaskingEngine
from pii_protect.storage import InMemoryStorage

async def main():
    async with PIIMaskingEngine(
        storage=InMemoryStorage(),
        encryption_key="<64-char hex string>",
    ) as engine:
        result = await engine.mask("Contact john@acme.com about GST 27AAPFU0939F1ZV", scope="doc-1")
        print(result.masked_text)
        # "Contact {{EMAIL:3f9a2b7c...}} about GST {{GST:9a03b7c1...}}"

        original = await engine.unmask(result.masked_text, scope="doc-1")
        print(original)
        # "Contact john@acme.com about GST 27AAPFU0939F1ZV"

        print(engine.redact("Contact john@acme.com about GST 27AAPFU0939F1ZV"))
        # "Contact [REDACTED:EMAIL] about GST [REDACTED:GST]"  -- irreversible, nothing stored

asyncio.run(main())
```

(`pii_protect_SALT` is assumed set in the environment for every example
below; pass `token_generator=DeterministicTokenGenerator(salt=...)`
explicitly if you'd rather not use an env var.)

`PIIMaskingEngine` is an async context manager -- `initialise()` connects
the storage backend, `close()` releases it. `async with` is the
recommended pattern; the sections below show both that and the manual
`initialise()`/`close()` lifecycle, for cases like a long-lived service
object where a context manager doesn't fit naturally.

---

## Scope: isolation and deletion, not just a label

Every masked value is tagged with a `scope` -- a free-form string
(customer ID, invoice ID, tenant ID; `None` for the unscoped/global
namespace). Scope isn't cosmetic:

- **Tokens are scope-bound.** The same PII value masked under two
  different scopes produces two different tokens. `unmask()` enforces
  this -- a token whose stored scope doesn't match the scope you pass is
  refused, not resolved.
- **Deletion is scope-based.** `delete_scope()` purges every record tied
  to one scope in a single call -- the natural shape for "this customer
  requested deletion" or "this document was removed."

Always pass the same `scope` to `mask()` and the matching `unmask()`
call for a given piece of text.

---

## The core operations

| Method                                     | Reversible?         | Touches storage? | Use for                                                                                  |
| ------------------------------------------ | ------------------- | ---------------- | ---------------------------------------------------------------------------------------- |
| `mask(text, scope=None)`                   | Yes, via `unmask()` | Yes              | Sending documents to an LLM/cloud service while keeping raw PII on-premise               |
| `unmask(masked_text, scope=None)`          | --                  | Yes (read)       | Restoring original values before writing back to source systems                          |
| `redact(text)`                             | **No**              | **No**           | Logs, analytics exports, anything that must never contain recoverable PII                |
| `render_partial_mask(text, result, rules)` | --                  | **No**           | Customer-facing display: "last 6 digits visible" without changing mask()/unmask() at all |
| `delete_scope(scope)`                      | --                  | Yes (write)      | Purging every value tied to a deleted customer/document/tenant                           |
| `rotate_encryption_key(new_key)`           | --                  | Yes (write)      | Re-encrypting the whole vault if the current key is suspected compromised                |

### `mask()` / `unmask()` -- with a context manager

```python
async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key) as engine:
    result = await engine.mask("Contact john@acme.com", scope="invoice-2026-00417")
    # result.masked_text     -> text with {{TYPE:xxxx...}} placeholders
    # result.token_count     -> number of PII spans masked
    # result.entity_counts   -> {"EMAIL": 1, ...}
    # result.entities        -> per-span detail (type, offsets, token, confidence, source)

    text_back = await engine.unmask(result.masked_text, scope="invoice-2026-00417")
```

### `mask()` / `unmask()` -- manual lifecycle (no context manager)

```python
engine = PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key)
await engine.initialise()   # connects the storage backend -- required before any call below

try:
    result = await engine.mask("Contact john@acme.com", scope="invoice-2026-00417")
    text_back = await engine.unmask(result.masked_text, scope="invoice-2026-00417")
finally:
    await engine.close()    # releases storage backend resources
```

### Inspecting _why_ something didn't unmask

```python
stats = await engine.unmask_with_stats(result.masked_text, scope="invoice-2026-00417")
print(stats.text)               # same as unmask(), with inline markers for problems
print(stats.tokens_resolved)    # successfully decrypted
print(stats.tokens_unresolved)  # token not found in storage at all -> "[UNRESOLVED]"
print(stats.tokens_denied)      # token found, but stored under a different scope -> "[SCOPE_DENIED]"
print(stats.tokens_tampered)    # token found, but failed decryption/tamper-check -> "[TAMPERED]"
```

A problem with one token never aborts resolution of the others in the
same call -- each token is resolved (or not) independently.

### `redact()` -- irreversible, synchronous, no engine lifecycle needed

```python
engine = PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key)
# redact() never touches storage, so it works even before initialise():
scrubbed = engine.redact("Contact john@acme.com about GST 27AAPFU0939F1ZV")
# "Contact [REDACTED:EMAIL] about GST [REDACTED:GST]"
```

---

## Working with dictionaries

`mask_dict()` / `unmask_dict()` operate on JSON-serialisable Python
dicts/lists, preserving structure while masking values at any depth --
including numeric leaves (e.g. a phone number stored as an `int`), which
are masked without corrupting the surrounding structure; a leaf keeps its
original type if nothing PII-like was found in it.

```python
async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key) as engine:
    data = {
        "vendor": {"name": "Acme Industries", "email": "john@acme.com"},
        "invoice_number": "INV-001",
        "contact_phone": 9876543210,   # numeric PII -- handled safely
    }

    masked = await engine.mask_dict(data, scope="doc-1")
    restored = await engine.unmask_dict(masked, scope="doc-1")
    assert restored == data
```

If you already know which fields contain PII, skip NER entirely with
`mask_dict_with_known_pii_keys()` -- only the values of the named keys
are masked, at any depth, regardless of whether they match a detection pattern:

```python
data = {
    "vendor_name": "Acme Industries",
    "invoice_number": "INV-001",
    "contact": {"email": "john@acme.com"},
}

masked = await engine.mask_dict_with_known_pii_keys(
    data, pii_keys=["vendor_name", "email"], scope="doc-1",
)
restored = await engine.unmask_dict_with_known_pii_keys(
    masked, pii_keys=["vendor_name", "email"], scope="doc-1",
)
```

---

## Partial masking (display-only)

For cases where a human needs to _see part_ of a value -- "last 6 digits
of an account number, everything else masked" -- without changing the
reversible `mask()`/`unmask()` flow at all:

```python
from pii_protect import PartialMaskRule

async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key) as engine:
    text = "Please debit account 004417803912, card 4111111111111111"
    result = await engine.mask(text, scope="acct-9001")   # completely normal, unchanged mask() call

    rendered = engine.render_partial_mask(
        text,                  # the ORIGINAL text, not result.masked_text
        result,                # the MaskResult from the mask() call above
        rules={
            "ACCOUNT":     PartialMaskRule(visible_chars=6, position="end"),
            "CREDIT_CARD": PartialMaskRule(visible_chars=4, position="end"),
        },
    )
    # "Please debit account ******803912, card ************1111"

    # the reversible flow is completely unaffected:
    original = await engine.unmask(result.masked_text, scope="acct-9001")
    assert original == text
```

`render_partial_mask` is a pure function over data you already have -- it
never calls the storage backend, the cipher, or the token generator.
Entity types with no rule configured fall back to full masking (every
character replaced), so nothing is left more visible than intended just
because a rule wasn't specified.

`PartialMaskRule` fields: `visible_chars` (how many characters stay
visible), `position` (`"start"` or `"end"` -- which end stays visible),
`mask_char` (default `"*"`).

---

## Scope deletion

```python
async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=key) as engine:
    await engine.mask("john@acme.com", scope="customer-4471")
    await engine.mask("jane@acme.com", scope="customer-4471")

    deleted_count = await engine.delete_scope("customer-4471")
    print(deleted_count)   # 2

    # any text masked under that scope is now permanently unresolvable:
    # stats.tokens_unresolved would be > 0 for those tokens from here on
```

Pass `scope=None` to purge everything stored under the unscoped/global
namespace.

---

## Key rotation

If the current encryption key is suspected compromised, re-encrypt the
whole vault under a new one:

```python
from pii_protect.crypto import AESGCMCipher

async with PIIMaskingEngine(storage=InMemoryStorage(), encryption_key=old_key) as engine:
    result = await engine.mask("john@acme.com", scope="doc-1")

    new_key = AESGCMCipher.generate_key()
    rotated_count = await engine.rotate_encryption_key(new_key)
    print(rotated_count)   # number of records re-encrypted

    # engine now uses new_key internally -- no other code changes needed:
    original = await engine.unmask(result.masked_text, scope="doc-1")
    assert original == "john@acme.com"
```

Rotation is two-phase: every record is decrypted and validated under the
**current** key first -- nothing is written during this phase -- and only
if every record passes does the engine re-encrypt and persist each one
under the new key. If any record fails to decrypt, the whole rotation
aborts before touching storage, and the engine keeps using its current
key, so a half-rotated vault is not a possible outcome.

---

## Architecture

```mermaid
flowchart TD

    ENGINE["PIIMaskingEngine<br/>(pii_protect.engine)<br/><br/>mask() . unmask() . redact()<br/>delete_scope() . rotate_encryption_key()<br/>render_partial_mask()"]

    subgraph NER["NEREngine (pii_protect.ner)"]
        REGEX["RegexNERLayer<br/>(always on, Luhn/SWIFT/UPI-validated)"]
        GLINER["GLiNERLayer<br/>(optional, offline-safe by default)"]
        SPACY["SpacyNERLayer<br/>(optional)"]
        PRIV["PrivacyFilterLayer<br/>(optional, offline-safe by default)"]
        MERGER["TokenizerSafeSpanMerger"]
        RESOLVER["SpanConflictResolver<br/>(containment-aware)"]

        REGEX --> MERGER
        GLINER --> MERGER
        SPACY --> MERGER
        PRIV --> MERGER
        MERGER --> RESOLVER
    end

    TOKEN["DeterministicTokenGenerator<br/>(pii_protect.tokens)<br/><br/>{{TYPE:xxxx...}} (128-bit, scope-bound)<br/>find_tokens_in_text()"]

    CRYPTO["AESGCMCipher<br/>(pii_protect.crypto)<br/><br/>AES-256-GCM<br/>encrypt() / decrypt()"]

    subgraph STORAGE["StorageBackend (pii_protect.storage)"]
        MEM["InMemoryStorage"]
        FILE["FileSystemStorage"]
        REDIS["RedisStorage"]
        PG["PostgresStorage"]
    end

    ENGINE -->|"mask()"| NER
    NER -->|"DetectedSpan[]"| TOKEN
    TOKEN -->|"token + value_hash + scope"| CRYPTO
    CRYPTO --> STORAGE

    ENGINE -->|"unmask() -- scope-checked per token"| TOKEN
    TOKEN --> CRYPTO
    CRYPTO --> STORAGE

    ENGINE -->|"delete_scope() / rotate_encryption_key()"| STORAGE

    ENGINE -.->|"redact()<br/>No encryption<br/>No storage"| ENGINE
```

### Components

**`PIIMaskingEngine`** (`pii_protect.engine`) is the single public entry
point. It owns one `NEREngine`, one `DeterministicTokenGenerator`, one
`AESGCMCipher`, and one `StorageBackend`, and wires them together for
every operation above. This is the only class most callers need to import.

**`NEREngine`** (`pii_protect.ner`) does detection only -- it never
touches encryption or storage. It runs one or more layers over the input
text and merges their output into a single non-overlapping span list:

- `RegexNERLayer` -- always on, no extra dependencies. High-precision
  patterns for structured PII: GST, PAN, TAN, IFSC, ABN, VAT, UEN, CRN,
  IBAN, SWIFT, account/sort-code numbers, credit cards, email, UPI,
  phone (India + international), invoice/PO references, URLs.
  `CREDIT_CARD` matches are Luhn-validated and `SWIFT` matches are
  checked against real ISO 3166-1 country codes, so ordinary numbers/words
  that merely have the right shape aren't flagged as PII.
- `GLiNERLayer` -- optional. Zero-shot on-premise NER for PERSON,
  ORGANISATION, ADDRESS, PASSPORT, DRIVING_LICENSE, USERNAME, and more.
  Requires `pii-protect[gliner]`.
- `SpacyNERLayer` -- optional. Adds PERSON / ORGANISATION / ADDRESS
  detection via a local spaCy model. Requires `pii-protect[spacy]`.
- `PrivacyFilterLayer` -- optional. Adds detection via any HuggingFace
  token-classification model you point it at, run entirely on-premise
  through `transformers.pipeline`. Requires `pii-protect[privacy-filter]`.

When layers disagree or overlap, `SpanConflictResolver` picks a winner: a
span fully contained inside another always loses to the larger one first
(so a short sub-pattern can never claim just a fragment of a longer,
correctly-matched value), then regex-validated spans win over semantic
ones, then financial entities win over PHONE, then higher confidence,
then longer span. `TokenizerSafeSpanMerger` separately stitches back
together sub-word fragments that some transformer models emit at token
boundaries.

**`DeterministicTokenGenerator`** (`pii_protect.tokens`) turns a detected
span into a `{{ENTITY_TYPE:xxxx...}}` placeholder -- a 32-hex-character
(128-bit) suffix derived from `SHA-256(NFC(value) | entity_type | scope | salt)`.
The same `(value, entity_type, scope)` triple always produces the same
token under one salt, which is what makes within-scope deduplication and
`find_tokens_in_text()` (used by `unmask()` to locate placeholders) work.
Binding `scope` into the derivation is what makes scope a real isolation
boundary rather than just a label on the stored record -- the same value
in two different scopes gets two different tokens. Values are
NFC-normalised before hashing, so the same human-readable value in a
different Unicode normalisation form (common across OSes/OCR pipelines)
still deduplicates correctly; the _encrypted_ value stored in the vault
is always the original, un-normalised text. A separate unsalted,
scope-independent `value_hash` is used purely for storage-side
deduplication lookups.

**`AESGCMCipher`** (`pii_protect.crypto`) is the only component that ever
sees plaintext PII outside of the `NEREngine`. Each value is encrypted
with AES-256-GCM using a fresh 96-bit IV, with the entity type bound in
as additional authenticated data (AAD) -- so a stored ciphertext can't be
replayed under a different entity type. Storage backends only ever
receive ciphertext, IV, and tag; they never see plaintext.

**`StorageBackend`** (`pii_protect.storage`) is an abstract interface
`PIIMaskingEngine` depends on exclusively, which is what makes storage
swappable without touching detection, tokenisation, or encryption code.
A backend implements:

| Method                                                 | Purpose                                                        |
| ------------------------------------------------------ | -------------------------------------------------------------- |
| `put(record)`                                          | Persist a new record (idempotent on token_value)               |
| `get(token_value)`                                     | Fetch one record                                               |
| `get_many(token_values)`                               | Fetch several records in as few round trips as possible        |
| `find_by_value_hash(value_hash, scope)`                | Within-scope dedup lookup                                      |
| `touch(token_value)`                                   | Bump access count                                              |
| `delete_by_scope(scope)`                               | Purge every record for a scope -- powers `delete_scope()`      |
| `all_records()`                                        | Async-iterate every record -- powers `rotate_encryption_key()` |
| `replace_ciphertext(token_value, ciphertext, iv, tag)` | Overwrite ciphertext in place -- also powers key rotation      |
| `log_access(...)` _(optional)_                         | Audit hook, no-op by default                                   |

Four implementations ship out of the box:

| Backend             | Persistence                                                    | Extra required          | Notes                                                      |
| ------------------- | -------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------- |
| `InMemoryStorage`   | None (process lifetime)                                        | --                      | tests, short scripts                                       |
| `FileSystemStorage` | Single JSON file, atomic writes, reloads from disk on every op | --                      | single-process, no external infra                          |
| `RedisStorage`      | Redis hashes per token                                         | `pii-protect[redis]`    | shared across processes/hosts                              |
| `PostgresStorage`   | Relational table, auto-migrated schema                         | `pii-protect[postgres]` | shared, queryable, audit-loggable, cascading scope deletes |

Writing a fifth backend (S3, DynamoDB, Vault, etc.) means subclassing
`StorageBackend` and implementing the methods above -- `PIIMaskingEngine`
needs no changes.

### Data flow

**mask()**: `NEREngine.detect()` finds spans -> for each span, compute
`value_hash` and check the backend for an existing token in this `scope`
(dedup) -> if new, derive the scope-bound token, guard against a
(vanishingly unlikely) token collision, `AESGCMCipher.encrypt()` the
value -> `StorageBackend.put()` the ciphertext/IV/tag/scope -> splice the
`{{TYPE:xxxx...}}` token into the text in place of the original span.

**unmask()**: `DeterministicTokenGenerator.find_tokens_in_text()` locates
every placeholder -> `StorageBackend.get_many()` fetches all matching
records in one round trip -> for each, the record's stored `scope` is
checked against the scope you passed (mismatch -> `[SCOPE_DENIED]`, no
plaintext returned) -> `AESGCMCipher.decrypt()` each (failure -> isolated
to that one token as `[TAMPERED]`, the rest still resolve) -> splice the
decrypted values back into the text. Tokens with no matching record at
all are left as `[UNRESOLVED]`. A problem with one token never aborts
resolution of the others in the same call.

**redact()**: `NEREngine.detect()` finds spans -> each span is replaced
in-place with `[REDACTED:ENTITY_TYPE]`. Nothing downstream of detection
is invoked -- no cipher, no storage -- which is what makes it genuinely
irreversible rather than just "not currently reversed."

**delete_scope()**: calls straight through to `StorageBackend.delete_by_scope()`.

**rotate_encryption_key()**: `StorageBackend.all_records()` streams every
record -> each is decrypted under the _current_ cipher and held in memory
(nothing written yet) -> only once every record has been validated is
each one re-encrypted under the new cipher and persisted via
`StorageBackend.replace_ciphertext()` -> the engine then switches to the
new cipher for all future operations.

### Design choices worth knowing about

- **Encryption keys are supplied by the caller**, not derived from or
  stored alongside vault data. This keeps a compromised storage backend
  from being sufficient on its own to decrypt anything.
- **Scope is cryptographically binding, not advisory.** It's part of the
  token derivation and enforced on every `unmask()` call, not just a
  field you can choose to filter by.
- **Detection is fully separated from storage.** You can swap
  `InMemoryStorage` for `PostgresStorage` without changing anything about
  how PII is found, and you can add GLiNER/spaCy/transformer layers
  without touching storage at all.
- **All storage backend methods are `async`**, including `InMemoryStorage`
  and `FileSystemStorage` -- so the same calling code works unmodified
  whether the backend is a Python dict or a networked database.
- **No component downloads anything on its own.** GLiNER and the
  transformer privacy filter default to offline-safe loading; they raise
  immediately if their weights aren't already cached rather than
  reaching out to the network.

---

## Configuring detection

```python
from pii_protect import NEREngine, PIIMaskingEngine
from pii_protect.storage import InMemoryStorage

ner = NEREngine(
    enable_gliner=True,                 # zero-shot PERSON/ORG/ADDRESS/PASSPORT/etc.
    gliner_model="gliner-community/gliner_small-v2.5",
    gliner_local_files_only=True,        # default: raise if weights aren't cached, never auto-download
    enable_spacy=True,                   # PERSON / ORGANISATION / ADDRESS
    spacy_model="en_core_web_sm",
    enable_privacy_filter=True,          # any HF token-classification model
    privacy_filter_model="your/token-classification-model",
    privacy_filter_threshold=0.5,
    privacy_filter_device="cpu",
)

engine = PIIMaskingEngine(storage=InMemoryStorage(), ner_engine=ner)
```

`NEREngine()` with no arguments runs regex detection only, with zero
extra dependencies.

### Warming the model cache

`GLiNERLayer` and `PrivacyFilterLayer` never download weights
automatically -- construction raises immediately if they aren't already
cached. Warm the cache once, ahead of time, from whatever provisioning
step your own application already uses (a build stage, a CI step, a
one-off setup script -- `pii-protect` has no opinion on which):

```python
from pii_protect.ner.prefetch import prefetch_gliner, prefetch_privacy_filter

prefetch_gliner()                                             # only if you use enable_gliner=True
prefetch_privacy_filter("your/token-classification-model")     # only if you use enable_privacy_filter=True
```

---

## Storage backend examples

```python
from pii_protect.storage import InMemoryStorage, FileSystemStorage, RedisStorage, PostgresStorage

InMemoryStorage()
FileSystemStorage("./vault.json")
RedisStorage("redis://localhost:6379/0")
PostgresStorage("postgresql://user:pass@host:5432/mydb")   # creates its own schema on connect()
```

Custom backend:

```python
from typing import AsyncIterator, Optional
from pii_protect.storage import StorageBackend
from pii_protect.types import TokenRecord

class MyBackend(StorageBackend):
    async def put(self, record: TokenRecord) -> None: ...
    async def get(self, token_value: str) -> Optional[TokenRecord]: ...
    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]: ...
    async def find_by_value_hash(self, value_hash: str, scope: Optional[str]) -> Optional[str]: ...
    async def touch(self, token_value: str) -> None: ...
    async def delete_by_scope(self, scope: Optional[str]) -> int: ...
    def all_records(self) -> AsyncIterator[TokenRecord]: ...
    async def replace_ciphertext(self, token_value: str, ciphertext: bytes, iv: bytes, tag: bytes) -> None: ...
```

---

## Error handling

```python
from pii_protect import (
    PIIShieldError,                # base class for everything below
    EngineNotInitialisedError,      # mask()/unmask() called before initialise()
    DecryptionError,                # AES-GCM tag verification failed
    TokenCollisionError,            # (near-impossible) two different values hashed to the same token
    InvalidInputError,              # mask()/unmask()/redact() called with a non-string
    KeyRotationError,                # rotate_encryption_key() aborted before writing anything
    StorageBackendError,            # backend-specific I/O/connection failure
    OptionalDependencyMissingError,  # used a backend/layer without its extra installed
)
```

`ValueError` is also raised directly (not as a `pii_protect` exception)
when constructing a `DeterministicTokenGenerator` without a salt -- see
[Required setup](#required-setup-encryption-key-and-salt).

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```
