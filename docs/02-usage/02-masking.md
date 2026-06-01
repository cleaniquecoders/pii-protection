# Masking

Masking renders a value partially or fully hidden for display or logs. Every
strategy implements `MaskStrategy::mask(string $value): string`, is `final`, and
is multibyte-safe. Masking is **one-way** — none of these are reversible.

## Strategies at a glance

| Strategy | Behaviour | Example output |
|----------|-----------|----------------|
| `TailStrategy` | Keep last N chars, mask the rest | `******6789` |
| `FullStrategy` | Mask every char | `**********` |
| `EmailStrategy` | Mask local-part, keep domain | `****@acme.com` |
| `HashStrategy` | One-way `sha256` digest | `f4b0…e21` |
| `CreditCardStrategy` | Keep last 4 digits, preserve grouping | `**** **** **** 1111` |
| `IpStrategy` | Mask the last octet/group | `192.168.1.**` |
| `NameStrategy` | Keep each word's initial | `J*** D**` |
| `NricStrategy` | Mask Malaysian MyKad digits, keep dashes | `******-**-****` |
| `RegexStrategy` | Mask substrings matching a pattern | (see [Detection](05-detection-and-tokenization.md)) |

## Examples

```php
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\HashStrategy;
use CleaniqueCoders\PiiProtection\Masking\CreditCardStrategy;
use CleaniqueCoders\PiiProtection\Masking\IpStrategy;
use CleaniqueCoders\PiiProtection\Masking\NameStrategy;
use CleaniqueCoders\PiiProtection\Masking\NricStrategy;

(new TailStrategy(visible: 4))->mask('0123456789');      // "******6789"
(new FullStrategy)->mask('0123456789');                  // "**********"
(new EmailStrategy)->mask('john.doe@acme.com');          // "****@acme.com"
(new HashStrategy)->mask('0123456789');                  // "f4b0…e21" (sha256)
(new CreditCardStrategy)->mask('4111 1111 1111 1111');   // "**** **** **** 1111"
(new IpStrategy)->mask('192.168.1.42');                  // "192.168.1.**"
(new NameStrategy)->mask('John Doe');                    // "J*** D**"
(new NricStrategy)->mask('900101-01-1234');              // "******-**-****"
```

## Configurable mask character

Every strategy accepts an optional `maskChar` (default `*`):

```php
(new TailStrategy(visible: 4, maskChar: '•'))->mask('0123456789'); // "••••••6789"
(new FullStrategy(maskChar: 'x'))->mask('abc');                    // "xxx"
```

## Strategy-specific options

### TailStrategy

`visible` controls how many trailing characters stay readable (default `4`). When
the value is shorter than or equal to `visible`, it is fully masked.

```php
(new TailStrategy(visible: 2))->mask('abcd'); // "**cd"
(new TailStrategy(visible: 4))->mask('abc');  // "***"  (length <= visible)
```

### EmailStrategy

Masks the local-part with a fixed token (default `****`) and keeps the domain.
With no `@`, the whole value is masked.

```php
(new EmailStrategy)->mask('jane@acme.com');                 // "****@acme.com"
(new EmailStrategy(maskedLocal: '***'))->mask('a@b.com');   // "***@b.com"
(new EmailStrategy)->mask('not-an-email');                  // "************"
```

### NricStrategy

Masks every digit of a Malaysian MyKad number by default, preserving dashes. Set
`keepBirthDate` to keep the leading 6-digit birth-date portion visible.

```php
(new NricStrategy)->mask('900101-01-1234');                    // "******-**-****"
(new NricStrategy(keepBirthDate: true))->mask('900101-01-1234'); // "900101-**-****"
```

### HashStrategy

Replaces the value with a one-way digest (default `sha256`). Use it for PII you
must compare but never reverse.

```php
(new HashStrategy)->mask('012345678');               // sha256 hex digest
(new HashStrategy(algo: 'sha512'))->mask('012345678');
```

## Next Steps

- [Redaction](04-redaction.md) — apply strategies across a whole payload.
- [Detection & Tokenization](05-detection-and-tokenization.md) — mask patterns in free text.
