# API Reference

A compact reference of every public class, contract, and method. All types are
under the `CleaniqueCoders\PiiProtection` namespace.

## Contracts (`\Contracts`)

| Type | Methods |
|------|---------|
| `Encrypter` | `encrypt(string $plain): string`, `decrypt(string $cipher): string` |
| `ContextualEncrypter` (extends `Encrypter`) | `encryptWithContext(string $plain, string $context): string`, `decryptWithContext(string $cipher, string $context): string` |
| `MaskStrategy` | `mask(string $value): string` |
| `Redactor` | `redact(array $data, array $fields): array` |
| `Vault` | `put(string $token, string $value): void`, `get(string $token): ?string`, `has(string $token): bool`, `forget(string $token): void` |

## Masking (`\Masking`)

Each implements `MaskStrategy`.

| Class | Constructor |
|-------|-------------|
| `TailStrategy` | `__construct(int $visible = 4, string $maskChar = '*')` |
| `FullStrategy` | `__construct(string $maskChar = '*')` |
| `EmailStrategy` | `__construct(string $maskedLocal = '****', string $maskChar = '*')` |
| `HashStrategy` | `__construct(string $algo = 'sha256')` |
| `CreditCardStrategy` | `__construct(int $visible = 4, string $maskChar = '*')` |
| `IpStrategy` | `__construct(string $maskChar = '*')` |
| `NameStrategy` | `__construct(string $maskChar = '*')` |
| `NricStrategy` | `__construct(bool $keepBirthDate = false, string $maskChar = '*')` |
| `RegexStrategy` | `__construct(string $pattern, MaskStrategy $inner = new FullStrategy)` |

See [Masking](../02-usage/02-masking.md) for behaviour and examples.

## Encryption (`\Encryption`)

### `OpenSslEncrypter` implements `ContextualEncrypter`

```php
__construct(string|KeyRing $key)
encrypt(string $plain): string
decrypt(string $cipher): string
encryptWithContext(string $plain, string $context): string
decryptWithContext(string $cipher, string $context): string
```

AES-256-GCM with per-message HKDF and a versioned format
(`v2.<keyId>.<payload>`); decrypts legacy 1.0/1.1 ciphertext transparently.

### `KeyRing`

```php
__construct(array $keys, ?string $currentId = null, ?string $legacyId = null)
static single(string $key, string $id = 'default'): self
currentId(): string
currentKey(): string
legacyKey(): string
get(string $id): string
```

Key ids must match `[A-Za-z0-9_-]+`. Throws `EncryptionException` for an empty
ring, invalid id, empty key material, or an unknown current/legacy id.

### `HmacBlindIndex`

```php
__construct(string $key, int $length = 64, ?callable $normaliser = null)
index(string $value): string
matches(string $value, string $storedIndex): bool
```

Deterministic HMAC-SHA256 index for searchable lookups. `length` is in hex
characters (1–64); `matches()` compares in constant time. Throws
`EncryptionException` for an empty key or out-of-range length.

## Redaction

### `ArrayRedactor` implements `Redactor`

```php
__construct(MaskStrategy $strategy)
redact(array $data, array $fields): array
```

`$fields` accepts plain names, `name => MaskStrategy` maps, and dot-path/wildcard
targets (`user.phone`, `users.*.phone`) in any combination. Recurses into nested
arrays and JSON-encoded strings.

### `ObjectRedactor`

```php
__construct(MaskStrategy $strategy)
redact(object $object): array
```

Masks public properties tagged with `#[Pii]` into an array; untagged properties
are copied; uninitialized typed properties become `null`.

### `Attributes\Pii`

```php
#[Attribute(Attribute::TARGET_PROPERTY)]
__construct(?string $strategy = null) // class-string<MaskStrategy>|null
```

## Detection (`\Detection`)

### `PiiScrubber`

```php
__construct(?MaskStrategy $strategy = null, ?array $types = null)
scrub(string $text): string
detect(string $text): array // [['type' => string, 'value' => string, 'offset' => int], ...]
```

Built-in detector types: `email`, `credit_card`, `nric`, `ipv4`, `phone`.
Default strategy is `FullStrategy`; default types are all of them.

## Tokenization (`\Tokenization`)

### `Tokenizer`

```php
__construct(Vault $vault, int $tokenBytes = 16)
tokenize(string $value): string   // returns "tok_<hex>"
detokenize(string $token): ?string
forget(string $token): void
```

### `ArrayVault` implements `Vault`

In-memory token store; methods as per the `Vault` contract.

## Convenience

### `PiiManager`

```php
__construct(Encrypter $encrypter, MaskStrategy $strategy)
encrypt(string $plain): string
decrypt(string $cipher): string
mask(string $value): string
redact(array $data, array $fields): array
```

## Exceptions (`\Exceptions`)

| Class | Extends | Thrown when |
|-------|---------|-------------|
| `PiiException` | `RuntimeException` | Base type for all package exceptions |
| `EncryptionException` | `PiiException` | Empty key, encryption failure, bad `KeyRing`/index config |
| `DecryptionException` | `PiiException` | Non-base64, too-short, tampered, or wrong key/context |

## Related Documentation

- [Usage](../02-usage/README.md)
- [Contracts](../01-architecture/02-contracts.md)
