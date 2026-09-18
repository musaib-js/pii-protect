# Changelog

## 0.3.2

### Fixed

- **A configured decoy could suppress a real detection and leave it
  unmasked.** 0.3.1 discarded categories after conflict resolution and gave a
  domain-declared span a priority bonus, so a declared category could take a
  span from a built-in one and then be dropped. With `real estate` declared
  and skipped, `"i live at 24 Mabini St, Cebu City"` masked only `Cebu City`
  -- the street address was claimed by the decoy at 0.79, discarded with it,
  and went out in the clear. Without the decoy it masked correctly.

  Both halves of that are reverted: skipping is back inside the GLiNER layer,
  and `_pick_winner` compares raw confidence again rather than the priority
  formula. Anyone running 0.3.1 with a declared category should move to this
  release.

### Changed

- **Skipping is a label, not an entity type, and the label is asked about in
  the same prediction.** `skip_entities` is replaced by `skip_labels`, and
  `PII_PROTECT_SKIP_ENTITIES` by `PII_PROTECT_SKIP_LABELS`, taking labels
  rather than category names.

  This is how `job title` always worked, now available to a deployment.
  Naming a label gives the model somewhere truer to put a span, so it stops
  assigning that span to the category it was getting wrong -- asking in a
  prediction of its own cannot do that, it can only override the answer
  afterwards. On `"what is the carpet area of my property"`, `"real estate"`
  asked alongside the built-in labels scores **0.92** and `ADDRESS` no longer
  claims the word at all; asked separately it scored 0.51 and had to win a
  contest to take the span.

  That also removes the need to tune a threshold for a decoy: 0.92 clears the
  default without configuration, where the separate-call score sat in a narrow
  band between 0.4 and 0.55. A per-label threshold is not possible anyway --
  the model takes one threshold per call, so giving each label its own would
  split them into separate predictions and lose the competition that makes
  this work.

  `job title` and `age group` are no longer a special case in the code: they
  are the default value of `DEFAULT_SKIP_LABELS`, the same setting a
  deployment configures. A deployment's labels are added to them, never
  substituted, so declaring one decoy cannot quietly start masking every job
  title. Label order is preserved, because the label list is part of the
  prompt -- moving `job title` to the end changed `"Engineer Santos"` from
  `PERSON 'Santos'` to `PERSON 'Engineer Santos'`.

## 0.3.1

### Fixed

- **A token now carries the category it was detected as.** Deduplication
  matches on the value alone, and `_store_span` returned the token it found
  before the entity type was consulted. A value masked once as one category
  and later detected as another was handed back the first token ever minted
  for it, still wearing the first category's label -- the placeholder said the
  wrong thing, the vault stored the wrong thing, and no amount of
  reconfiguring the detector changed either.

  This surfaced as soon as deployments began declaring their own categories: a
  word reclaimed from `PERSON` by a domain label kept masking as `PERSON`. The
  stored record's category is now checked before its token is reused, and a
  mismatch mints a token for the category actually detected. Tokens derive
  from the category as well as the value, so the two cannot collide, and
  re-masking under the original category still finds its original token.
  Deduplication within a category, scope isolation and the unmask round-trip
  are unchanged.

### Changed

- **Which of GLiNER's categories are discarded is now a deployment's choice.**
  Superseded by 0.3.2, which replaces `skip_entities` with `skip_labels`.
  `JOB_TITLE` and `AGE_GROUP` were skipped by a hardcoded check.
  `NEREngine(skip_entities=[...])` replaces that list, taking `EntityType`
  members or plain strings, and `PII_PROTECT_SKIP_ENTITIES` sets it from the
  environment -- the other half of `PII_PROTECT_DOMAIN_ENTITIES`, which is
  what declares the category in the first place. Declaring one without
  skipping it only renames the false positive, so both have to be settable
  without a code change. An explicit argument wins over the variable, which
  wins over `DEFAULT_SKIPPED_ENTITIES`; unset keeps the default while
  `PII_PROTECT_SKIP_ENTITIES=` says explicitly to discard nothing.

  Skipping runs after conflict resolution, so a discarded category still
  competes for its characters first. That is what lets a declared category
  take a span away from a built-in one before being dropped: on "what is the
  carpet area of my property", GLiNER reads "property" as an ADDRESS, and
  declaring "real estate" then skipping it leaves the sentence untouched
  while a real address in the same sentence still masks.

  Both categories are asked about so the model does not file them under
  something that *is* masked, while neither is private on its own. Naming a
  category here is also how to deal with a recurring false positive: give the
  model a truer label for what it keeps mislabelling, then discard that
  label's answers.

## 0.3.0

### Added

- **Domain-specific entity layer, detected by GLiNER.** Deployments can
  declare their own PII categories in configuration instead of waiting for a
  library release. `NEREngine(domain_entities="rules.json")` takes a JSON
  file, a list of dicts, bare label strings, or `DomainEntity` objects;
  setting `PII_PROTECT_DOMAIN_ENTITIES` to a config path adds categories to
  an already-deployed service with no code change at all.

  A rule is a GLiNER label -- a plain-English phrase such as `"customer
  reference number"` -- plus an optional `name`, `threshold`, and
  `context_words` that require nearby wording before a match counts. The
  categories are found zero-shot by the same model as the built-in ones, so
  declaring any implies `enable_gliner=True`.

  A declared name is registered as a real `EntityType` member, so it flows
  through masking, token round-tripping, `redact()`, `ignore_entities`,
  entity counts and partial-mask rules exactly like a built-in category.
  Naming an existing category routes matches to it rather than creating a
  new one. Rules are validated when they load, so a malformed one fails at
  startup with a message naming it.

  When a configured rule and a built-in category match the same span, the
  configured rule wins -- a deployment describing its own identifiers is
  the better authority than a general-purpose pattern.

- **`detect_entities`, the mirror image of `ignore_entities`.** `mask()`,
  `mask_dict()` and `redact()` take a list of categories to detect for that
  call only, in the same shapes `domain_entities` accepts:
  `await engine.mask(text, detect_entities=["policy number"])`. Pass
  `allow_detect_entities=True` to `NEREngine` to load GLiNER for it when no
  categories are configured up front.

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