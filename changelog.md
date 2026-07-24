# Changelog

## 0.2.1

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