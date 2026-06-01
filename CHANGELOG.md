# Changelog

All notable changes to `pii-protection` will be documented in this file.

## 1.3.0 - 2026-06-01

Object/DTO redaction and tokenization. Non-breaking; stays within 1.x.

### Added

- **`#[Pii]` attribute + `ObjectRedactor`** — tag public properties of an object/DTO and redact them into an array. A tag may name its own `MaskStrategy`; untagged properties are copied through untouched; uninitialized properties become `null`.
- **`Tokenizer` + `Vault`** — replace a PII value with an opaque, random token (`tok_...`) reversible only through a vault. Ships with an in-memory `ArrayVault`; implement the `Vault` contract to persist tokens elsewhere.

**Full changelog:** https://github.com/cleaniquecoders/pii-protection/blob/main/CHANGELOG.md

## 1.2.0 - 2026-06-01

Encryption hardening and free-text PII detection. Backward compatible with 1.0/1.1 ciphertext — no breaking changes.

### Added

- **Context binding (AAD)** via `ContextualEncrypter` — `encryptWithContext()` / `decryptWithContext()` bind ciphertext to a context (user id, column name); the same context is required to decrypt.
- **Key rotation** via `KeyRing` — new ciphertext uses the current key; older ciphertext decrypts with whichever key its id points to. No big-bang re-encryption.
- **HKDF-SHA256** per-message key derivation, with a random salt, for the new versioned ciphertext.
- **`HmacBlindIndex`** — deterministic, one-way index for searchable equality lookups on encrypted data.
- **`PiiScrubber`** + **`RegexStrategy`** — scrub PII (email, credit card, Malaysian NRIC, IPv4, phone) out of free text, plus arbitrary patterns.

### Changed

- `OpenSslEncrypter` now writes a self-describing versioned format (`v2.<keyId>.<payload>`) and accepts either a key string or a `KeyRing`.

### Backward compatibility

Ciphertext produced by 1.0/1.1 still decrypts unchanged via the legacy path — the `v2.` prefix is unambiguous because `.` is not a base64 character.

**Full changelog:** https://github.com/cleaniquecoders/pii-protection/blob/main/CHANGELOG.md

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
