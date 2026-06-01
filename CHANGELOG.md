# Changelog

All notable changes to `pii-protection` will be documented in this file.

## 1.1.0 - 2026-06-01

Masking, redaction & developer-experience enhancements. Fully backward compatible — no breaking changes.

### Added

- New masking strategies: `CreditCardStrategy`, `IpStrategy`, `NameStrategy`, and `NricStrategy` (Malaysian MyKad).
- Configurable mask character (`maskChar`, default `*`) on `TailStrategy`, `FullStrategy`, and `EmailStrategy`.
- Per-field strategy map in `ArrayRedactor` — map each field to its own `MaskStrategy` in a single pass, mixable with plain field names.
- Dot-path & wildcard targeting in `ArrayRedactor` (`user.phone`, `users.*.phone`), usable as values or strategy-mapped keys.
- Exception hierarchy: `PiiException` (base), `EncryptionException`, `DecryptionException` — all extend `RuntimeException`.
- PHPStan at `level: max` with a dedicated CI workflow; Pest native mutation testing via `composer test-mutate`.

### Notes

- `OpenSslEncrypter` now throws the typed exceptions above instead of a bare `RuntimeException` (still a subclass — existing catch blocks keep working).
- The `Redactor` payload phpdoc widened to `array<array-key, mixed>` (more permissive, non-breaking).

**Full changelog:** https://github.com/cleaniquecoders/pii-protection/blob/main/CHANGELOG.md

## [Unreleased]

## 1.0.0 - 2026-05-31

Initial release — pure-PHP, framework-agnostic PII protection primitives. Constructor-injected, contract-based, zero framework dependencies.

### Added

- **Contracts** — `Encrypter`, `MaskStrategy`, and `Redactor` interfaces so consumers depend on abstractions, not concretions.
- **Masking strategies** (all `final`, multibyte-safe): `TailStrategy` (keep last N chars, default 4), `FullStrategy` (mask everything), `EmailStrategy` (mask local-part, keep domain), `HashStrategy` (one-way `sha256`).
- **Encryption** — `OpenSslEncrypter` using AES-256-GCM with a random IV per call, GCM authentication-tag verification, and a `#[\SensitiveParameter]` key injected via the constructor.
- **Redaction** — `ArrayRedactor` that walks nested arrays and JSON-encoded string values, masking listed fields and leaving the rest untouched.
- **Wrapper** — `PiiManager` convenience facade over an `Encrypter` and a `MaskStrategy`.
- Pest test suite (40 tests) covering masking edge cases, encrypter round-trips/tamper rejection, and redaction over flat/nested/JSON payloads.

### Requirements

PHP `^8.4`, `ext-openssl`, `ext-mbstring`.

### Install

```bash
composer require cleaniquecoders/pii-protection


```
**Guardrail:** never encrypt a value used in a lookup / equality / uniqueness check — ciphertext is non-deterministic and won't match. Mask or hash those instead.
