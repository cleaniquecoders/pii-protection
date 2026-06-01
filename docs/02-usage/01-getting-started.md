# Getting Started

Install the package and run your first encrypt, mask, and redact. Everything is
constructor-injected, so there is no configuration step.

## Requirements

- PHP `^8.4`
- `ext-openssl`
- `ext-mbstring`

## Installation

```bash
composer require cleaniquecoders/pii-protection
```

## The PiiManager wrapper

`PiiManager` bundles an `Encrypter` and a `MaskStrategy` behind one object — the
quickest way to get going.

```php
use CleaniqueCoders\PiiProtection\PiiManager;
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

$manager = new PiiManager(
    new OpenSslEncrypter(key: $appKey),
    new TailStrategy(visible: 4),
);

$cipher = $manager->encrypt('0123456789');  // persist at rest
$plain  = $manager->decrypt($cipher);        // "0123456789"

$masked = $manager->mask('0123456789');       // "******6789" for display
$audit  = $manager->redact($payload, ['phone', 'national_id']);
```

> **Tip**: `PiiManager` is a convenience. For full control — context binding,
> key rotation, per-field strategies — use the underlying classes directly. See
> [Encryption](03-encryption.md) and [Redaction](04-redaction.md).

## Using the primitives directly

```php
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\ArrayRedactor;

$encrypter = new OpenSslEncrypter(key: $appKey);
$cipher = $encrypter->encrypt('secret');

$masked = (new EmailStrategy)->mask('john.doe@acme.com'); // "****@acme.com"

$clean = (new ArrayRedactor(new EmailStrategy))->redact(
    ['email' => 'john@acme.com', 'name' => 'Jane'],
    ['email'],
);
```

## Guardrail

> **Warning**: Never query on an encrypted column — ciphertext is
> non-deterministic and will not match across rows. Use an `HmacBlindIndex` for
> lookups, or `mask`/`hash` the value. See
> [Searchable lookups](03-encryption.md#searchable-lookups-blind-index).

## Next Steps

- [Masking](02-masking.md)
- [Encryption & Key Rotation](03-encryption.md)
- [Redaction](04-redaction.md)
