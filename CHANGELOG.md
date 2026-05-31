# Changelog

All notable changes to `pii-protection` will be documented in this file.

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
