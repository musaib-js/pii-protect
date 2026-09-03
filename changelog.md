# Changelog

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