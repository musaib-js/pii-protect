# pii-protect

A pluggable, on-premise-first PII masking, unmasking, and redaction library for Python.

`pii-protect` detects personally identifiable and sensitive business
information in free text (emails, phone numbers, GST/PAN/IBAN numbers,
person and organisation names, bank details, invoice/PO numbers, and more),
and gives you three ways to handle it:

- **mask** it into a reversible placeholder token, encrypted at rest
- **unmask** a previously masked token back to its original value
- **redact** it permanently, with no way to recover the original

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
pip install "pii-protect[privacy-filter]"     # + transformer token-classification layer
pip install "pii-protect[all]"                # everything
```

Only `cryptography` is a hard dependency. `asyncpg`, `redis`, `spacy`, and
`transformers`/`torch` are all opt-in extras. If you use a backend or
detection layer without installing its extra, you get a clear
`OptionalDependencyMissingError` telling you exactly what to install —
never a bare `ImportError` or a silent failure.

---

## Quick start

```python
import asyncio
from pii_protect import PIIMaskingEngine
from pii_protect.storage import InMemoryStorage

async def main():
    async with PIIMaskingEngine(storage=InMemoryStorage()) as engine:
        result = await engine.mask("Contact john@acme.com about GST 27AAPFU0939F1ZV")
        print(result.masked_text)
        # "Contact {{EMAIL:abcc2}} about GST {{GST:9a03b}}"

        original = await engine.unmask(result.masked_text)
        print(original)
        # "Contact john@acme.com about GST 27AAPFU0939F1ZV"

        print(engine.redact("Contact john@acme.com about GST 27AAPFU0939F1ZV"))
        # "Contact [REDACTED:EMAIL] about GST [REDACTED:GST]"  — irreversible, nothing stored

asyncio.run(main())
```

`PIIMaskingEngine` is an async context manager — `initialise()` connects
the storage backend, `close()` releases it. Use `async with` unless you
need to control that lifecycle yourself.

---

## The three operations

| Method | Reversible? | Touches storage? | Use for |
|---|---|---|---|
| `mask(text, scope=None)` | Yes, via `unmask()` | Yes | Sending documents to an LLM/cloud service while keeping raw PII on-premise |
| `unmask(masked_text, scope=None)` | — | Yes (read) | Restoring original values before writing back to source systems |
| `redact(text)` | **No** | **No** | Logs, analytics exports, anything that must never contain recoverable PII |

```python
result = await engine.mask(text, scope="invoice-2026-00417")
# result.masked_text     -> text with {{TYPE:xxxxx}} placeholders
# result.token_count     -> number of PII spans masked
# result.entity_counts   -> {"EMAIL": 1, "GST": 1, ...}
# result.entities        -> per-span detail (type, offsets, token, confidence, source)

text_back = await engine.unmask(result.masked_text, scope="invoice-2026-00417")

scrubbed = engine.redact(text)   # synchronous — no storage or encryption involved
```

`mask_dict()` / `unmask_dict()` do the same over JSON-serialisable dicts,
masking all string leaf values in one pass so a repeated value across
fields still maps to the same token.

`scope` is a free-form string (e.g. a document or invoice ID). The same
PII value repeated within one scope deduplicates to a single stored token
instead of being encrypted and stored twice — pass the same scope to
`mask()` and the matching `unmask()` call.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │             PIIMaskingEngine             │
                    │        (pii_protect.engine)               │
                    │                                           │
                    │   mask()    unmask()    redact()          │
                    └───────┬───────────┬───────────┬───────────┘
                            │           │           │
              ┌─────────────┘           │           └─── (redact never
              │                         │                  leaves this box —
              ▼                         │                  no encrypt, no store)
   ┌─────────────────────┐              │
   │      NEREngine        │            │
   │   (pii_protect.ner)     │            │
   │                        │            │
   │  RegexNERLayer   (always on)        │
   │  SpacyNERLayer   (optional)         │
   │  PrivacyFilterLayer (optional)      │
   │        │                            │
   │  TokenizerSafeSpanMerger            │
   │  SpanConflictResolver               │
   └──────────┬─────────────┘            │
              │ DetectedSpan[]           │
              ▼                          │
   ┌─────────────────────┐               │
   │ DeterministicToken-   │             │
   │ Generator              │             │
   │ (pii_protect.tokens)    │             │
   │                        │             │
   │  {{TYPE:xxxxx}}        │             │
   │  find_tokens_in_text() │◄────────────┘
   └──────────┬─────────────┘
              │ token, value_hash
              ▼
   ┌─────────────────────┐        ┌───────────────────────────────┐
   │   AESGCMCipher        │       │        StorageBackend           │
   │  (pii_protect.crypto)   │──────▶       (pii_protect.storage)       │
   │                        │       │                                 │
   │  encrypt() / decrypt() │       │  InMemoryStorage                │
   │  AES-256-GCM            │      │  FileSystemStorage               │
   └────────────────────────┘       │  RedisStorage       (extra)      │
                                     │  PostgresStorage    (extra)      │
                                     └───────────────────────────────┘
```

### Components

**`PIIMaskingEngine`** (`pii_protect.engine`) is the single public entry
point. It owns one `NEREngine`, one `DeterministicTokenGenerator`, one
`AESGCMCipher`, and one `StorageBackend`, and wires them together for
`mask()` / `unmask()` / `redact()`. This is the only class most callers
need to import.

**`NEREngine`** (`pii_protect.ner`) does detection only — it never touches
encryption or storage. It runs one or more layers over the input text and
merges their output into a single non-overlapping span list:

- `RegexNERLayer` — always on, no extra dependencies. High-precision
  patterns for structured PII: GST, PAN, TAN, ABN, VAT, IBAN, SWIFT,
  account/sort-code/routing numbers, credit cards, email, phone
  (India + international), invoice and PO references.
- `SpacyNERLayer` — optional. Adds PERSON / ORGANISATION / ADDRESS
  detection via a local spaCy model. Requires `pii-protect[spacy]`.
- `PrivacyFilterLayer` — optional. Adds detection via any HuggingFace
  token-classification model you point it at, run entirely on-premise
  through `transformers.pipeline`. Requires `pii-protect[privacy-filter]`.

When layers disagree or overlap, `SpanConflictResolver` picks a winner
(regex-validated spans win first, then financial-entity-over-phone,
then higher confidence, then longer span), and
`TokenizerSafeSpanMerger` stitches back together sub-word fragments
that some transformer models emit at token boundaries.

**`DeterministicTokenGenerator`** (`pii_protect.tokens`) turns a detected
span into a `{{ENTITY_TYPE:xxxxx}}` placeholder — a 5-hex-character
suffix derived from `SHA-256(value | entity_type | salt)`. Same value +
same entity type always produces the same token within one salted
instance, which is what makes within-document deduplication and
`find_tokens_in_text()` (used by `unmask()` to locate placeholders) work.
It also computes an unsalted `value_hash` used purely for storage-side
deduplication, so multiple engine instances backed by the same storage
can recognise a value they've each seen before, even though their
salted tokens differ.

**`AESGCMCipher`** (`pii_protect.crypto`) is the only component that ever
sees plaintext PII outside of the `NEREngine`. Each value is encrypted
with AES-256-GCM using a fresh 96-bit IV, with the entity type bound in
as additional authenticated data (AAD) — so a stored ciphertext can't be
replayed under a different entity type. Storage backends only ever
receive ciphertext, IV, and tag; they never see plaintext.

**`StorageBackend`** (`pii_protect.storage`) is an abstract interface with
five methods a backend must implement: `put`, `get`, `get_many`,
`find_by_value_hash`, `touch` (plus an optional `log_access` audit hook).
`PIIMaskingEngine` depends only on this interface, which is what makes
storage swappable without touching detection, tokenisation, or
encryption code. Four implementations ship out of the box:

| Backend | Persistence | Extra required | Notes |
|---|---|---|---|
| `InMemoryStorage` | None (process lifetime) | — | tests, short scripts |
| `FileSystemStorage` | Single JSON file, atomic writes | — | single-process, no external infra |
| `RedisStorage` | Redis hashes per token | `pii-protect[redis]` | shared across processes/hosts |
| `PostgresStorage` | Relational table, auto-migrated schema | `pii-protect[postgres]` | shared, queryable, audit-loggable |

Writing a fifth backend (S3, DynamoDB, Vault, etc.) means subclassing
`StorageBackend` and implementing those five methods — `PIIMaskingEngine`
needs no changes.

### Data flow

**mask()**: `NEREngine.detect()` finds spans → for each span, compute
`value_hash` and check the backend for an existing token in this `scope`
(dedup) → if new, `AESGCMCipher.encrypt()` the value → `StorageBackend.put()`
the ciphertext/IV/tag → splice the `{{TYPE:xxxxx}}` token into the text in
place of the original span.

**unmask()**: `DeterministicTokenGenerator.find_tokens_in_text()` locates
every placeholder → `StorageBackend.get_many()` fetches all matching
records in one round trip → `AESGCMCipher.decrypt()` each → splice the
decrypted values back into the text. Tokens with no matching record are
left in place with a `[UNRESOLVED]` suffix rather than raising, so a
partially-available vault degrades instead of failing the whole call.

**redact()**: `NEREngine.detect()` finds spans → each span is replaced
in-place with `[REDACTED:ENTITY_TYPE]`. Nothing downstream of detection
is invoked — no cipher, no storage — which is what makes it genuinely
irreversible rather than just "not currently reversed."

### Design choices worth knowing about

- **Encryption keys are supplied by the caller**, not derived from or
  stored alongside vault data. This keeps a compromised storage backend
  from being sufficient on its own to decrypt anything, and keeps key
  rotation an application-level concern independent of which storage
  backend you choose.
- **Detection is fully separated from storage.** You can swap
  `InMemoryStorage` for `PostgresStorage` without changing anything about
  how PII is found, and you can add spaCy/transformer layers without
  touching storage at all.
- **All storage backend methods are `async`**, including `InMemoryStorage`
  and `FileSystemStorage` — so the same calling code works unmodified
  whether the backend is a Python dict or a networked database.

---

## Configuring detection

```python
from pii_protect import NEREngine, PIIMaskingEngine
from pii_protect.storage import InMemoryStorage

ner = NEREngine(
    enable_spacy=True,                 # PERSON / ORGANISATION / ADDRESS
    spacy_model="en_core_web_sm",
    enable_privacy_filter=True,        # any HF token-classification model
    privacy_filter_model="your/token-classification-model",
    privacy_filter_threshold=0.5,
    privacy_filter_device="cpu",
)

engine = PIIMaskingEngine(storage=InMemoryStorage(), ner_engine=ner)
```

`NEREngine()` with no arguments runs regex detection only, with zero
extra dependencies.

---

## Encryption key

```python
from pii_protect.crypto import AESGCMCipher

engine = PIIMaskingEngine(storage=..., encryption_key="<64-char hex string>")
# or
engine = PIIMaskingEngine(storage=..., encryption_key=AESGCMCipher.generate_key())
```

If you omit `encryption_key`, an ephemeral one is generated and a warning
is logged — anything masked in that session becomes permanently
unrecoverable once the process exits. Always pass a stable key outside of
quick experiments; losing the key makes every previously masked value
permanently unrecoverable, by design.

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
from pii_protect.storage import StorageBackend
from pii_protect.types import TokenRecord

class MyBackend(StorageBackend):
    async def put(self, record: TokenRecord) -> None: ...
    async def get(self, token_value: str) -> TokenRecord | None: ...
    async def get_many(self, token_values: list[str]) -> dict[str, TokenRecord]: ...
    async def find_by_value_hash(self, value_hash: str, scope: str | None) -> str | None: ...
    async def touch(self, token_value: str) -> None: ...
```

---

## Error handling

```python
from pii_protect import (
    PIIShieldError,               # base class for everything below
    EngineNotInitialisedError,     # mask()/unmask() called before initialise()
    DecryptionError,               # AES-GCM tag verification failed
    StorageBackendError,           # backend-specific I/O/connection failure
    OptionalDependencyMissingError, # used a backend/layer without its extra installed
)
```

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```