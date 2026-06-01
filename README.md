# PII Protection

[![Latest Version on Packagist](https://img.shields.io/packagist/v/cleaniquecoders/pii-protection.svg?style=flat-square)](https://packagist.org/packages/cleaniquecoders/pii-protection)
[![Tests](https://img.shields.io/github/actions/workflow/status/cleaniquecoders/pii-protection/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/cleaniquecoders/pii-protection/actions/workflows/run-tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/cleaniquecoders/pii-protection.svg?style=flat-square)](https://packagist.org/packages/cleaniquecoders/pii-protection)
[![PHP Version](https://img.shields.io/packagist/dependency-v/cleaniquecoders/pii-protection/php?style=flat-square)](https://packagist.org/packages/cleaniquecoders/pii-protection)
[![License](https://img.shields.io/github/license/cleaniquecoders/pii-protection?style=flat-square)](LICENSE.md)

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

Each strategy implements `MaskStrategy::mask(string $value): string`.

| Strategy | Behaviour | Reversible |
|----------|-----------|------------|
| `TailStrategy` | Keep last N chars, mask the rest (`******6789`) | No |
| `FullStrategy` | Mask every char (`**********`) | No |
| `EmailStrategy` | Mask local-part, keep domain (`****@acme.com`) | No |
| `HashStrategy` | Replace with a one-way `sha256` digest | No |
| `CreditCardStrategy` | Keep last 4 digits, preserve grouping (`**** **** **** 1111`) | No |
| `IpStrategy` | Mask the last octet/group (`192.168.1.**`) | No |
| `NameStrategy` | Keep each word's initial (`J*** D**`) | No |
| `NricStrategy` | Mask MyKad digits, keep dashes (`******-**-****`) | No |

```php
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\HashStrategy;
use CleaniqueCoders\PiiProtection\Masking\CreditCardStrategy;
use CleaniqueCoders\PiiProtection\Masking\IpStrategy;
use CleaniqueCoders\PiiProtection\Masking\NameStrategy;
use CleaniqueCoders\PiiProtection\Masking\NricStrategy;

(new TailStrategy(visible: 4))->mask('0123456789');   // "******6789"
(new FullStrategy())->mask('0123456789');             // "**********"
(new EmailStrategy())->mask('john.doe@acme.com');     // "****@acme.com"
(new HashStrategy())->mask('0123456789');             // "f4b0...e21" (sha256)
(new CreditCardStrategy())->mask('4111 1111 1111 1111'); // "**** **** **** 1111"
(new IpStrategy())->mask('192.168.1.42');             // "192.168.1.**"
(new NameStrategy())->mask('John Doe');               // "J*** D**"
(new NricStrategy())->mask('900101-01-1234');         // "******-**-****"
```

Every strategy takes an optional `maskChar` (default `*`) so you can render with
`•`, `x`, or any character:

```php
(new TailStrategy(visible: 4, maskChar: '•'))->mask('0123456789'); // "••••••6789"
```

### Encryption at rest

`OpenSslEncrypter` uses AES-256-GCM. The key is injected via the constructor —
the library never reads env/config. Each message uses a random IV and a random
HKDF salt, so encrypting the same value twice yields different ciphertext.

```php
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;

$encrypter = new OpenSslEncrypter(key: $appKey);

$cipher = $encrypter->encrypt('012345678'); // store this
$plain  = $encrypter->decrypt($cipher);     // "012345678"
```

Ciphertext is written in a self-describing, versioned format
(`v2.<keyId>.<payload>`). Ciphertext produced by 1.0/1.1 still decrypts
unchanged — upgrades are seamless.

**Context binding (AAD)** — bind ciphertext to a context (user id, column name)
so it cannot be moved between rows/columns. The same context is required to
decrypt:

```php
$cipher = $encrypter->encryptWithContext('012345678', 'user:123');
$plain  = $encrypter->decryptWithContext($cipher, 'user:123'); // wrong context throws
```

**Key rotation** — give it a `KeyRing` with multiple keys: new ciphertext uses
the current key, while older ciphertext keeps decrypting with whichever key its
id points to. No big-bang re-encryption needed.

```php
use CleaniqueCoders\PiiProtection\Encryption\KeyRing;

$encrypter = new OpenSslEncrypter(new KeyRing(
    ['2024' => $oldKey, '2025' => $newKey],
    currentId: '2025', // encrypt with this; '2024' ciphertext still decrypts
));
```

### Searchable lookups (blind index)

Encryption is non-deterministic, so you cannot query an encrypted column. Store
a deterministic `HmacBlindIndex` alongside the ciphertext and query that instead
— it is one-way and only confirms a match, never reveals the value.

```php
use CleaniqueCoders\PiiProtection\Encryption\HmacBlindIndex;

$blind = new HmacBlindIndex(key: $indexKey);

$row = [
    'email_cipher' => $encrypter->encrypt($email),  // for retrieval/display
    'email_index'  => $blind->index($email),        // for WHERE email_index = ?
];

$blind->matches($email, $row['email_index']); // true
```

### Scrubbing free text

`PiiScrubber` masks PII patterns inside free text (log lines, messages), not
just named fields — with built-in detectors for email, credit card, Malaysian
NRIC, IPv4 and phone numbers.

```php
use CleaniqueCoders\PiiProtection\Detection\PiiScrubber;

(new PiiScrubber)->scrub('contact john@acme.com from 192.168.1.42');
// "contact ************* from ************"

(new PiiScrubber)->detect($logLine); // [['type' => 'email', 'value' => ..., 'offset' => ...], ...]
```

Or mask any custom pattern with `RegexStrategy`:

```php
use CleaniqueCoders\PiiProtection\Masking\RegexStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

(new RegexStrategy('/\d{10}/', new TailStrategy(visible: 4)))->mask('ref 0123456789');
// "ref ******6789"
```

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

**Per-field strategies** — map each field to its own strategy in a single pass
(plain field names still use the redactor's default strategy):

```php
$clean = $redactor->redact($payload, [
    'email' => new EmailStrategy,
    'phone' => new TailStrategy(visible: 4),
    'nric'  => new HashStrategy,
    'name',  // uses the default strategy
]);
```

**Dot-path & wildcard targeting** — target a precise location instead of any key
with that name; `*` matches any key at that level:

```php
$clean = $redactor->redact($payload, [
    'user.phone',        // only user.phone, not a top-level "phone"
    'users.*.phone',     // every users[].phone
    'contact.email' => new EmailStrategy,
]);
```

### Redacting objects / DTOs

Tag properties with `#[Pii]` and let `ObjectRedactor` mask them into an array.
A tag can name its own strategy; otherwise the redactor's default is used.

```php
use CleaniqueCoders\PiiProtection\Attributes\Pii;
use CleaniqueCoders\PiiProtection\ObjectRedactor;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;

class User
{
    public function __construct(
        #[Pii] public string $name,
        #[Pii(strategy: EmailStrategy::class)] public string $email,
        public int $age, // untagged — copied through untouched
    ) {}
}

$clean = (new ObjectRedactor(new FullStrategy))->redact($user);
// ['name' => '********', 'email' => '****@acme.com', 'age' => 30]
```

### Tokenization

Swap a PII value for an opaque, random token and keep the mapping in a `Vault`.
An in-memory `ArrayVault` ships with the package; implement `Vault` to persist
tokens elsewhere.

```php
use CleaniqueCoders\PiiProtection\Tokenization\Tokenizer;
use CleaniqueCoders\PiiProtection\Tokenization\ArrayVault;

$tokenizer = new Tokenizer(new ArrayVault);

$token = $tokenizer->tokenize('012345678'); // "tok_9f3a..." — reveals nothing
$tokenizer->detokenize($token);             // "012345678"
$tokenizer->forget($token);                 // drop the mapping
```

## Errors

Encryption/decryption failures throw a typed exception under
`CleaniqueCoders\PiiProtection\Exceptions\`: `EncryptionException` and
`DecryptionException`, both extending `PiiException` (itself a `RuntimeException`,
so existing catch blocks keep working).

## Guardrail — never encrypt lookup values

> **Never query on an encrypted column.** Ciphertext is non-deterministic
> (random IV + salt per call) and will not match across rows or queries. To
> support equality lookups, store an `HmacBlindIndex` alongside the ciphertext
> and query that — or `mask`/`hash` the value if you don't need to reverse it.

## Architecture

```text
src/
├── Contracts/
│   ├── Encrypter.php          # encrypt(string): string ; decrypt(string): string
│   ├── ContextualEncrypter.php # adds AAD-bound encrypt/decrypt
│   ├── MaskStrategy.php       # mask(string): string
│   ├── Redactor.php           # redact(array $data, array $fields): array
│   └── Vault.php              # token <-> value store contract
├── Masking/
│   ├── TailStrategy.php       # keep last N chars (default 4)
│   ├── FullStrategy.php       # mask everything
│   ├── EmailStrategy.php      # mask local-part, keep domain
│   ├── HashStrategy.php       # one-way (sha256) for non-reversible PII
│   ├── CreditCardStrategy.php # keep last 4 digits, preserve grouping
│   ├── IpStrategy.php         # mask the last octet/group
│   ├── NameStrategy.php       # keep each word's initial
│   ├── NricStrategy.php       # mask Malaysian MyKad digits, keep dashes
│   └── RegexStrategy.php      # mask substrings matching a pattern
├── Encryption/
│   ├── OpenSslEncrypter.php   # AES-256-GCM, HKDF, AAD, versioned format
│   ├── KeyRing.php            # multi-key holder for key rotation
│   └── HmacBlindIndex.php     # deterministic index for searchable lookups
├── Detection/
│   └── PiiScrubber.php        # detect/scrub PII patterns in free text
├── Tokenization/
│   ├── Tokenizer.php          # value <-> opaque token
│   └── ArrayVault.php         # in-memory Vault implementation
├── Attributes/
│   └── Pii.php                # #[Pii] property marker
├── Exceptions/
│   ├── PiiException.php        # base (extends RuntimeException)
│   ├── EncryptionException.php
│   └── DecryptionException.php
├── ArrayRedactor.php          # nested + JSON + per-field + dot-path redaction
├── ObjectRedactor.php         # redacts #[Pii]-tagged object properties
└── PiiManager.php             # convenience wrapper over strategy + encrypter
```

### Design notes

1. **Single responsibility per class.** Strategies, encrypter, redactor, and the
   wrapper are independent and swappable; consumers depend on the contracts, not
   the concretions.
2. **Configurable visible tail.** `TailStrategy(visible: N)` — default 4.
3. **Nested / JSON PII.** `ArrayRedactor` recurses, so structured columns are
   covered, not just flat scalars.
4. **Key handling is the caller's job.** `OpenSslEncrypter` takes a key (or a
   `KeyRing`) in its constructor; the library never reads env/config. Rotation
   is supported via the ring, but loading/storing keys is up to you.

## Documentation

Full documentation lives in [`docs/`](docs/README.md):

- [Architecture](docs/01-architecture/README.md) — primitives, contracts, design decisions.
- [Usage](docs/02-usage/README.md) — masking, encryption & key rotation, redaction, detection, tokenization.
- [Development](docs/03-development/README.md) — testing, quality tooling, releases.
- [API Reference](docs/04-api/README.md) — every public class and method.

## Testing

```bash
composer test          # Pest test suite
composer analyse       # PHPStan (level max)
composer test-mutate   # Pest mutation testing (needs a coverage driver)
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
