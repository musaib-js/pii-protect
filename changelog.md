# Changelog

## 0.2.9

### Added

- **Domain-specific entity layer.** Deployments can declare their own PII
  categories in configuration instead of waiting for a library release.
  `NEREngine(domain_entities="rules.json")` takes a JSON file, a list of
  dicts, or `DomainEntity` objects; setting `PII_PROTECT_DOMAIN_ENTITIES`
  to a config path adds categories to an already-deployed service with no
  code change at all.

  Each rule is a name, a regex, an optional confidence, and optional
  `context_words` that require nearby wording before a match counts --
  which is what lets a loose shape like eight digits be declared safely.

  A declared name is registered as a real `EntityType` member, so it flows
  through masking, token round-tripping, `redact()`, `ignore_entities`,
  entity counts and partial-mask rules exactly like a built-in category.
  Naming an existing category adds a pattern to it rather than creating a
  new one. Rules are validated when they load, so a bad pattern fails at
  startup with a message naming the rule.

  When a configured rule and a built-in category match the same span, the
  configured rule wins -- a deployment describing its own identifiers is
  the better authority than a general-purpose pattern.

## 0.2.8

### Fixed

- **Age groups being detected as persons** `mask()` used to detect age groups like minor, junior etc as persons because the label age group itself was missing. Added the label and put that into the ignored labelled list, so that it is not masked.

## 0.2.7

### Fixed

- **PII detection no longer blocks the event loop.** `mask()` awaited
  nothing before calling `_ner.detect()`, so detection — synchronous CPU
  work, a regex sweep with the default layers and a GLiNER or transformer
  forward pass with them enabled — ran inline and froze every other
  coroutine in the process for its duration.

  The cost compounded with concurrency. Nine simultaneous masks of a 1.1KB
  text took 23.3s in total and all finished together at the end, because a
  caller's read timeout is counted from when the request was sent rather
  than when the server picked it up: requests at the back spent their whole
  timeout queued and were cancelled having done no work, surfacing as
  `httpx.ReadTimeout` rather than as slowness.

  Detection now runs via `asyncio.to_thread`. The detector layers hold no
  mutable state after construction — the models are read-only forward passes
  and the span merger and conflict resolver take and return values — so they
  are safe to enter from several threads. spaCy is the exception its own
  docs warn about, and `enable_spacy` already defaults to `False`.

  `redact()` makes the same inline call but is a sync function and is left
  as it is; making it async would break its signature for every caller.
  `unmask()` needed no change, as it runs no detection.

## 0.2.6

### Added

- **Vehicle/license plate number detection.** The regex layer now
  recognises license plates for India, the Philippines, the US, the
  UAE, and Saudi Arabia as a new `VEHICLE_NUMBER` entity type. A match
  requires a nearby "plate"/"vehicle no"/"registration no" label, since
  a plate's letters+digits shape alone is indistinguishable from an
  invoice code, coupon code, or tracking number.

### Fixed

- **Indian plate numbers no longer get misclassified as IBAN.** The
  Indian plate format (e.g. `KA05MH1234`) also happens to fit the (very
  permissive) IBAN pattern's shape. An IBAN candidate is now skipped
  when a vehicle-context label sits nearby, so a labelled plate number
  is masked as `VEHICLE_NUMBER` instead of `IBAN`.

## 0.2.5

### Added

- **New Philippines-specific detection: TIN, government IDs, student IDs,
  medical record numbers.** The regex layer now recognises the BIR Tax
  Identification Number (`TIN`), government-issued IDs (`PH_GOVT_ID`:
  SSS, GSIS, PhilHealth, Pag-IBIG, UMID, PhilSys), `STUDENT_ID`, and
  `MEDICAL_RECORD_NUMBER`. Each requires a nearby label (e.g. "TIN",
  "SSS", "Student ID") rather than matching on digit shape alone, since
  these shapes are otherwise too generic to detect reliably.
- **PIN and OTP codes are now masked.** A 4-6 digit number found near the
  word "PIN" or "OTP" (case-insensitive) is now detected and masked as
  `PIN`/`OTP` respectively.
- **`ignore_entities` parameter on `mask()`, `mask_dict()`, and
  `redact()`.** Callers can now pass a list of entity types (as
  `EntityType` members or plain strings, e.g. `["ORGANISATION", "PIN"]`)
  to exclude from masking for that call -- matching spans are left
  exactly as detected instead of being tokenised/redacted.

## 0.2.4

### Fixed

- ** False positives for job titles in GLiNER person detection. Job titles such as CEO, CFO, CTO, branch manager, and account manager could previously be incorrectly classified as person names by the GLiNER layer. The GLiNER label set now includes job title as a competing entity type, allowing the model to distinguish job roles from actual person names. Job-title detections are subsequently ignored and are not returned as PII entities.

## 0.2.3

### Added

- **`PostgresStorage` schema is now configurable via the `PII_SCHEMA` env
  var.** Resolution order is: explicit `schema=` constructor arg, then
  the `PII_SCHEMA` environment variable, then `"public"` if neither is
  set.

### Fixed

- **International phone numbers with irregular spacing are now detected.**
  A number like `+632 8811 8866` with more than one space between digit
  groups (e.g. `+632  8811 8866`) previously wasn't matched by the
  international phone pattern and leaked through in cleartext. The
  pattern now tolerates multiple spaces/hyphens between groups.

## 0.2.2

### Fixed

- **SWIFT code Detection.** The post-regex validation layer has been enhanced to detect SWIFT Codes efficiently by removing the  need of contextual information present in the adjacent text.
- **Person name detection.** The GLiNER layer threshold has been reduced to 0.5 to detect the Indian origin names that 
  were missed by 0.6 threshold


## 0.2.1

### Enhanced

- **Aadhar numbers are now detected.** The regex layer has been enhanced to detect aadhar numbers and
  also validate them using verhoeff algorithm to make sure every 12 digit number that looks like an
  Aadhar number is not tagged as an Aadhar number.


### Fixed

- **PO and Invoice Reference Removed as PII Types** PO Number and Invoice Number, which don't essentially qualify
  to be PII items have been removed.

- **False positive for names in GLiNER fixed.** Words like Hi, Ha whenever given individually to the model were tagged
  as person, which is a classical issue with zero-shot NER detection. It has been fixed with a post NER validator
  based on the length of the word.


- No changes to how encryption, scopes, or tokens work — this release is
  entirely about detection accuracy for Aadhar cards and the false positive resolutions



## 0.2.0

### Renamed

- The salt environment variable is now `PII_PROTECT_SALT`.

### Fixed

- **Emails with spaces around the `@` are now detected.** A value like
  `john @ acme.com` — a common artefact of manual entry or OCR — used to
  pass through `mask()` and `redact()` untouched. It's now recognised as
  an email address like any other.

- **Phone numbers in parentheses are now detected.** A format like
  `(98765)43210` previously wasn't matched by any pattern and leaked
  through in cleartext. It's now caught as a phone number.

- **Spaced Indian mobile numbers are now detected in full.** A number
  written as `98765 43210` previously wasn't matched at all. It's now
  detected and masked/redacted as a complete number — not just part of it.

- **Bank code (SWIFT/BIC) detection no longer flags ordinary capitalised
  words.** Words like `CHECKING`, `SHIPMENT`, and `DEADLINE` were
  sometimes being masked or redacted as if they were bank codes, because
  the previous check only validated part of the code's structure and a
  meaningful fraction of random 8-letter words happen to pass it by pure
  coincidence. Detection now also requires the text to actually look like
  a bank-code context (e.g. near the word "SWIFT" or "BIC"), which
  matches how these codes actually appear in real documents and removes
  the false positives without losing real ones.

- **Masking and then unmasking a dictionary no longer changes a value's
  type.** A field whose value was a numeric-looking string (e.g.
  `"9876543210"`, or something like `"0076543210"` with a leading zero)
  used to come back as a number instead of a string after a mask/unmask
  round trip — silently changing its type and, for values with leading
  zeros, its content. Values now always come back in their original type.

### Notes

- No changes to how encryption, scopes, or tokens work — this release is
  entirely about detection accuracy and the dictionary round-trip fix
  above.