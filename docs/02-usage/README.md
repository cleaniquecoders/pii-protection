# Usage

Task-oriented guides for applying the package to real problems. Each page is
self-contained and uses runnable code from the public API.

## Table of Contents

### [1. Getting Started](01-getting-started.md)

Install the package and run your first encrypt, mask, and redact with
`PiiManager`.

### [2. Masking](02-masking.md)

Every `MaskStrategy` — tail, full, email, hash, credit card, IP, name, NRIC,
and regex — with examples and the configurable mask character.

### [3. Encryption & Key Rotation](03-encryption.md)

Encrypt at rest with `OpenSslEncrypter`, bind context with AAD, rotate keys with
`KeyRing`, and enable searchable lookups with `HmacBlindIndex`.

### [4. Redaction](04-redaction.md)

Mask sensitive fields inside arrays (`ArrayRedactor`) and objects/DTOs
(`ObjectRedactor` + `#[Pii]`), including per-field strategies and dot-path
targeting.

### [5. Detection & Tokenization](05-detection-and-tokenization.md)

Scrub PII out of free text with `PiiScrubber`, and swap values for opaque tokens
with `Tokenizer`.

## Related Documentation

- [Architecture](../01-architecture/README.md) — the concepts behind these APIs.
- [API Reference](../04-api/README.md) — every class and method.
