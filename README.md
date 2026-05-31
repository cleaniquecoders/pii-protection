# PII Protection

[![Latest Version on Packagist](https://img.shields.io/packagist/v/cleaniquecoders/pii-protection.svg?style=flat-square)](https://packagist.org/packages/cleaniquecoders/pii-protection) [![Tests](https://img.shields.io/github/actions/workflow/status/cleaniquecoders/pii-protection/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/cleaniquecoders/pii-protection/actions/workflows/run-tests.yml) [![Total Downloads](https://img.shields.io/packagist/dt/cleaniquecoders/pii-protection.svg?style=flat-square)](https://packagist.org/packages/cleaniquecoders/pii-protection)

Pure-PHP PII protection: field-level **encryption at rest** + **masking** of
sensitive fields in audit/log payloads. No framework, no global state — plain
classes with explicit inputs and outputs, usable anywhere.

A small library of portable primitives every app handling personal data
(SOC 2 / PDPA / GDPR) needs:

- **Encryption** — reversible encrypt/decrypt of PII for storage at rest (AES-256-GCM).
- **Masking** — render a value partially or fully hidden for display or logs.
- **Redaction** — walk a key/value payload (e.g. change-log old/new values) and
  mask listed fields before it is persisted.

Everything is constructor-injected. No service container, no boot conventions,
no static facades — so it drops into Laravel, Symfony, Slim, a CLI tool, a queue
worker, or plain PHP unchanged.

## Requirements

- PHP `^8.4`
- `ext-openssl`
- `ext-mbstring`

## Installation

You can install the package via composer:

```bash
composer require cleaniquecoders/pii-protection
```

## Usage

### Quick start

```php
use CleaniqueCoders\PiiProtection\PiiManager;
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

$manager = new PiiManager(
    new OpenSslEncrypter(key: $appKey),
    new TailStrategy(visible: 4),
);

$cipher = $manager->encrypt('0123456789');  // persist at rest
$plain  = $manager->decrypt($cipher);       // "0123456789"

$masked = $manager->mask('0123456789');      // "******6789" for display
$audit  = $manager->redact($payload, ['phone', 'national_id']);
```

### Masking strategies

Each strategy implements `MaskStrategy::mask(string $value): string`.

| Strategy | Behaviour | Reversible |
|----------|-----------|------------|
| `TailStrategy` | Keep last N chars, mask the rest (`******6789`) | No |
| `FullStrategy` | Mask every char (`*********`) | No |
| `EmailStrategy` | Mask local-part, keep domain (`****@acme.com`) | No |
| `HashStrategy` | Replace with a one-way `sha256` digest | No |

```php
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\HashStrategy;

(new TailStrategy(visible: 4))->mask('0123456789'); // "******6789"
(new FullStrategy())->mask('0123456789');           // "**********"
(new EmailStrategy())->mask('john.doe@acme.com');   // "****@acme.com"
(new HashStrategy())->mask('0123456789');           // "f4b0...e21" (sha256)
```

### Encryption at rest

`OpenSslEncrypter` uses AES-256-GCM. The key is injected via the constructor —
the library never reads env/config and never manages key rotation.

```php
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;

$encrypter = new OpenSslEncrypter(key: $appKey);

$cipher = $encrypter->encrypt('012345678'); // store this
$plain  = $encrypter->decrypt($cipher);     // "012345678"
```

Each call uses a random IV/nonce, so encrypting the same value twice yields
different ciphertext.

### Redaction of payloads

`ArrayRedactor` generalises change-log masking: given a payload (e.g. with
`old_values` / `new_values`, or any nested key/value map) and a list of
sensitive fields, it applies the chosen `MaskStrategy` to each listed field —
recursing into nested arrays and JSON-decoded structures — and leaves every
other field untouched.

```php
use CleaniqueCoders\PiiProtection\ArrayRedactor;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

$redactor = new ArrayRedactor(new TailStrategy(visible: 4));

$clean = $redactor->redact($payload, ['phone', 'national_id']);
```

## Guardrail — never encrypt lookup values

> **Never encrypt a value used in a lookup / equality / uniqueness check.**
> Ciphertext is non-deterministic (random IV per call) and will not match across
> rows or queries. **Mask or hash** those values instead.

## Architecture

```text
src/
├── Contracts/
│   ├── Encrypter.php          # encrypt(string): string ; decrypt(string): string
│   ├── MaskStrategy.php       # mask(string): string
│   └── Redactor.php           # redact(array $data, array $fields): array
├── Masking/
│   ├── TailStrategy.php       # keep last N chars (default 4)
│   ├── FullStrategy.php       # mask everything
│   ├── EmailStrategy.php      # mask local-part, keep domain
│   └── HashStrategy.php       # one-way (sha256) for non-reversible PII
├── Encryption/
│   └── OpenSslEncrypter.php   # AES-256-GCM, key injected via constructor
├── ArrayRedactor.php          # walks nested arrays, applies a MaskStrategy
└── PiiManager.php             # convenience wrapper over strategy + encrypter
```

**Design notes**

1. **Single responsibility per class.** Strategies, encrypter, redactor, and the
   wrapper are independent and swappable; consumers depend on the contracts, not
   the concretions.
2. **Configurable visible tail.** `TailStrategy(visible: N)` — default 4.
3. **Nested / JSON PII.** `ArrayRedactor` recurses, so structured columns are
   covered, not just flat scalars.
4. **Key handling is the caller's job.** `OpenSslEncrypter` takes a key in its
   constructor; the library never reads env/config or manages key rotation.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](https://github.com/spatie/.github/blob/main/CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security vulnerabilities.

## Credits

- [Nasrul Hazim Bin Mohamad](https://github.com/nasrulhazim)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
