# Encryption & Key Rotation

`OpenSslEncrypter` provides reversible, authenticated encryption (AES-256-GCM)
for PII at rest. The key is injected via the constructor — the library never
reads env/config. Each message uses a random IV and a random HKDF salt, so
encrypting the same value twice yields different ciphertext.

## Basic encryption

```php
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;

$encrypter = new OpenSslEncrypter(key: $appKey);

$cipher = $encrypter->encrypt('012345678'); // store this
$plain  = $encrypter->decrypt($cipher);     // "012345678"
```

Ciphertext is written in a self-describing, versioned format
(`v2.<keyId>.<payload>`). Ciphertext produced by 1.0/1.1 still decrypts
unchanged — see
[Backward compatibility](../01-architecture/03-design-decisions.md#backward-compatibility-1x-guarantee).

## Context binding (AAD)

Bind ciphertext to a context — a user id, a column name — so it cannot be moved
between rows or columns. The same context is required to decrypt; a mismatch
throws `DecryptionException`.

```php
$cipher = $encrypter->encryptWithContext('012345678', 'user:123');
$plain  = $encrypter->decryptWithContext($cipher, 'user:123');

// Wrong context fails authentication:
$encrypter->decryptWithContext($cipher, 'user:999'); // throws DecryptionException
```

`encrypt()`/`decrypt()` are equivalent to an empty context.

## Key rotation with a KeyRing

Give the encrypter a `KeyRing` of multiple keys. New ciphertext uses the current
key; older ciphertext keeps decrypting with whichever key its id points to — no
big-bang re-encryption.

```php
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Encryption\KeyRing;

$encrypter = new OpenSslEncrypter(new KeyRing(
    ['2024' => $oldKey, '2025' => $newKey],
    currentId: '2025', // encrypt with this; '2024' ciphertext still decrypts
));

$encrypter->encrypt('x'); // "v2.2025.…"
```

### Legacy ciphertext and the legacy key

Pre-1.2 (unversioned) ciphertext is decrypted with the ring's **legacy** key,
which defaults to the current key. If you rotated away from the key that wrote
your old data, point `legacyId` at it:

```php
$ring = new KeyRing(
    ['k1' => $originalKey, 'k2' => $newKey],
    currentId: 'k2',
    legacyId: 'k1', // pre-1.2 ciphertext was written with k1
);
```

A single-key ring (the common case) is created automatically when you pass a
string key, or explicitly with `KeyRing::single($key)`.

## Searchable lookups (blind index)

Encryption is non-deterministic, so you cannot query an encrypted column. Store
a deterministic `HmacBlindIndex` alongside the ciphertext and query that instead.
The index is one-way: it confirms a match but never reveals the value.

```php
use CleaniqueCoders\PiiProtection\Encryption\HmacBlindIndex;

$blind = new HmacBlindIndex(key: $indexKey);

$row = [
    'email_cipher' => $encrypter->encrypt($email), // for retrieval/display
    'email_index'  => $blind->index($email),       // for WHERE email_index = ?
];

$blind->matches($email, $row['email_index']); // true (constant-time compare)
```

Make lookups case-insensitive by supplying a normaliser (apply the **same** one
at write and query time), and trade storage for collision-resistance with
`length` (hex characters, 1–64):

```php
$blind = new HmacBlindIndex(
    key: $indexKey,
    length: 32,
    normaliser: fn (string $v) => strtolower(trim($v)),
);
```

## Errors

Failures throw typed exceptions: `EncryptionException` and `DecryptionException`,
both extending `PiiException` (a `RuntimeException`). See
[API Reference](../04-api/README.md#exceptions).

## Next Steps

- [Design Decisions](../01-architecture/03-design-decisions.md)
- [Redaction](04-redaction.md)
