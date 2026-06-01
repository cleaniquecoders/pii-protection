# Redaction

Redaction masks listed sensitive fields inside a structure while leaving
everything else untouched. Use `ArrayRedactor` for key/value payloads (change
logs, audit records, API bodies) and `ObjectRedactor` for objects/DTOs.

## ArrayRedactor

Given a payload and a list of fields, `ArrayRedactor` applies a `MaskStrategy` to
each listed field — recursing into nested arrays and JSON-decoded strings — and
returns a new array.

```php
use CleaniqueCoders\PiiProtection\ArrayRedactor;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

$redactor = new ArrayRedactor(new TailStrategy(visible: 4));

$clean = $redactor->redact($payload, ['phone', 'national_id']);
```

Plain field names match a key at **any depth**, and values that are JSON strings
are decoded, redacted, and re-encoded.

### Per-field strategies

Map each field to its own strategy in a single pass. Plain names (no arrow) fall
back to the redactor's default strategy.

```php
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\HashStrategy;

$clean = $redactor->redact($payload, [
    'email' => new EmailStrategy,
    'phone' => new TailStrategy(visible: 4),
    'nric'  => new HashStrategy,
    'name', // uses the default strategy
]);
```

### Dot-path & wildcard targeting

Target a precise location instead of any key with that name. `*` matches any key
at that level.

```php
$clean = $redactor->redact($payload, [
    'user.phone',        // only user.phone, not a top-level "phone"
    'users.*.phone',     // every users[].phone
    'contact.email' => new EmailStrategy,
]);
```

> **Note**: Dot-path targeting walks nested arrays. Plain field names also reach
> into JSON-encoded string values; combine both as needed.

## ObjectRedactor

Tag public properties with `#[Pii]` and `ObjectRedactor` masks them into an
array. A tag may name its own strategy; untagged properties are copied through;
uninitialized typed properties become `null`.

```php
use CleaniqueCoders\PiiProtection\Attributes\Pii;
use CleaniqueCoders\PiiProtection\ObjectRedactor;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
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

> **Note**: A strategy named in `#[Pii(strategy: ...)]` is instantiated with no
> constructor arguments, so it uses that strategy's own defaults (for example
> `TailStrategy`'s default of 4 visible characters).

## Next Steps

- [Masking](02-masking.md) — the strategies you can plug in.
- [Detection & Tokenization](05-detection-and-tokenization.md)
