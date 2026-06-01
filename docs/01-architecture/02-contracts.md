# Contracts

Consumers depend on interfaces, not concrete classes. This keeps call sites
stable and lets you swap implementations (a different cipher, a custom masking
rule, a persistent vault) without changing the code that uses them.

All contracts live in the `CleaniqueCoders\PiiProtection\Contracts` namespace.

## Encrypter

Reversible encryption for storage at rest.

```php
namespace CleaniqueCoders\PiiProtection\Contracts;

interface Encrypter
{
    public function encrypt(string $plain): string;

    public function decrypt(string $cipher): string;
}
```

The shipped implementation is
[`OpenSslEncrypter`](../02-usage/03-encryption.md) (AES-256-GCM).

## ContextualEncrypter

Extends `Encrypter` with AEAD context binding (additional authenticated data).
The same context supplied at encryption is required to decrypt.

```php
namespace CleaniqueCoders\PiiProtection\Contracts;

interface ContextualEncrypter extends Encrypter
{
    public function encryptWithContext(string $plain, string $context): string;

    public function decryptWithContext(string $cipher, string $context): string;
}
```

Because `encrypt()`/`decrypt()` are equivalent to an empty context, any
`ContextualEncrypter` is also a valid `Encrypter`.

## MaskStrategy

A single, total function from a value to its masked representation.

```php
namespace CleaniqueCoders\PiiProtection\Contracts;

interface MaskStrategy
{
    public function mask(string $value): string;
}
```

Strategies are independent and composable — `ArrayRedactor`, `ObjectRedactor`,
`RegexStrategy`, and `PiiScrubber` all take a `MaskStrategy`. See
[Masking](../02-usage/02-masking.md).

## Redactor

Walks a key/value payload and masks listed fields.

```php
namespace CleaniqueCoders\PiiProtection\Contracts;

interface Redactor
{
    /**
     * @param  array<array-key,mixed>  $data
     * @param  array<int|string,string|MaskStrategy>  $fields
     * @return array<array-key,mixed>
     */
    public function redact(array $data, array $fields): array;
}
```

`$fields` accepts plain names, name-to-strategy maps, and dot-path/wildcard
targets in any combination — see [Redaction](../02-usage/04-redaction.md). The
shipped implementation is `ArrayRedactor`.

## Vault

Stores the mapping between a token and its original value for tokenization.

```php
namespace CleaniqueCoders\PiiProtection\Contracts;

interface Vault
{
    public function put(string $token, string $value): void;

    public function get(string $token): ?string;

    public function has(string $token): bool;

    public function forget(string $token): void;
}
```

The package ships an in-memory `ArrayVault`; implement `Vault` to persist tokens
in a cache or database. See
[Tokenization](../02-usage/05-detection-and-tokenization.md).

## Next Steps

- [Design Decisions](03-design-decisions.md)
- [API Reference](../04-api/README.md)
