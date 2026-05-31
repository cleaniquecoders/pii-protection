# Changelog

All notable changes to `pii-protection` will be documented in this file.

## 1.0.0 - 2026-06-01

Initial release — pure-PHP PII protection primitives, framework-agnostic and constructor-injected.

### Added

- **Contracts** — `Encrypter`, `MaskStrategy`, and `Redactor` interfaces so consumers depend on abstractions, not concretions.
- **Masking strategies** (all `final`, multibyte-safe):
  - `TailStrategy` — keep the last N characters (default 4), mask the rest.
  - `FullStrategy` — mask every character.
  - `EmailStrategy` — mask the local-part, keep the domain.
  - `HashStrategy` — one-way `sha256` digest for non-reversible PII.
- **Encryption** — `OpenSslEncrypter` using AES-256-GCM with a random IV per call, GCM authentication-tag verification, and a `#[\SensitiveParameter]` key injected via the constructor.
- **Redaction** — `ArrayRedactor` that walks nested arrays and JSON-encoded string values, masking listed fields and leaving the rest untouched.
- **Wrapper** — `PiiManager` convenience facade over an `Encrypter` and a `MaskStrategy`.
- README documenting usage, the masking strategies, and the "never encrypt lookup values" guardrail.
- Pest test suite (40 tests) covering masking edge cases, encrypter round-trips/tamper rejection, and redaction over flat/nested/JSON payloads.
