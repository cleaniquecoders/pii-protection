# Changelog

All notable changes to `pii-protection` will be documented in this file.

## v1.0.0 — Initial release - 2026-05-31

First stable release of **pii-protection** — pure-PHP, framework-agnostic PII protection primitives. Constructor-injected, contract-based, zero framework dependencies. Runs in Laravel, Symfony, Slim, CLI tools, queue workers, or plain PHP.

### Highlights

- **Contracts** — `Encrypter`, `MaskStrategy`, `Redactor` so consumers depend on abstractions.
- **Masking strategies** (all `final`, multibyte-safe):
  - `TailStrategy` — keep last N chars (default 4), mask the rest
  - `FullStrategy` — mask every char
  - `EmailStrategy` — mask local-part, keep domain
  - `HashStrategy` — one-way `sha256` for non-reversible PII
  
- **Encryption** — `OpenSslEncrypter` (AES-256-GCM, random IV per call, GCM tag verification, `#[\SensitiveParameter]` key).
- **Redaction** — `ArrayRedactor` recurses nested arrays and JSON-encoded strings, masking listed fields only.
- **Wrapper** — `PiiManager` over an `Encrypter` + `MaskStrategy`.

### Requirements

- PHP `^8.4`, `ext-openssl`, `ext-mbstring`

### Install

```bash
composer require cleaniquecoders/pii-protection

```
### Guardrail

Never encrypt a value used in a lookup / equality / uniqueness check — ciphertext is non-deterministic and won't match. Mask or hash those instead.

**Full changelog:** see [CHANGELOG.md](https://github.com/cleaniquecoders/pii-protection/blob/main/CHANGELOG.md)

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
