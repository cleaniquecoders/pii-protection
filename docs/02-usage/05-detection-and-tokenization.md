# Detection & Tokenization

Capabilities for data that does not arrive as neat named fields: scrubbing PII
and secrets out of free text, and replacing values with opaque tokens.

## Scrubbing free text

`PiiScrubber` masks PII patterns inside arbitrary text — log lines, messages,
notes — using built-in detectors for email, credit card, Malaysian NRIC, IPv4,
and phone numbers. Detectors run in a fixed order so broader patterns (credit
cards) are masked before narrower ones can partially match them.

```php
use CleaniqueCoders\PiiProtection\Detection\PiiScrubber;

(new PiiScrubber)->scrub('contact john@acme.com from 192.168.1.42');
// "contact ************* from ************"
```

### Detect without modifying

`detect()` reports what it found, with type and byte offset, leaving the text
intact.

```php
$found = (new PiiScrubber)->detect('email john@acme.com ip 192.168.1.42');
// [
//   ['type' => 'email', 'value' => 'john@acme.com', 'offset' => 6],
//   ['type' => 'ipv4',  'value' => '192.168.1.42',  'offset' => 23],
// ]
```

### Choosing detectors and the mask strategy

Pass a `MaskStrategy` (default `FullStrategy`) and limit which detector types run:

```php
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

$scrubber = new PiiScrubber(
    strategy: new TailStrategy(visible: 4),
    types: ['email', 'nric'], // only these detectors
);
```

### Custom patterns with RegexStrategy

`RegexStrategy` masks every substring matching a pattern, delegating each match
to an inner strategy. It is also a `MaskStrategy`, so it composes anywhere.

```php
use CleaniqueCoders\PiiProtection\Masking\RegexStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

(new RegexStrategy('/\d{10}/', new TailStrategy(visible: 4)))->mask('ref 0123456789');
// "ref ******6789"
```

## Scrubbing secrets

`SecretScrubber` is the sibling of `PiiScrubber`, for **machine credentials**
instead of personal data.

The separation is deliberate. PII detectors look for email, phone, NRIC and IP;
secret detectors look for keys, tokens and passwords. The sets do not overlap,
and running the wrong one does real damage — an infrastructure log with every
IP and email removed is no longer debuggable.

```php
use CleaniqueCoders\PiiProtection\Detection\SecretScrubber;

(new SecretScrubber)->scrub('DB_PASSWORD=hunter2 APP_ENV=production');
// "DB_PASSWORD=[redacted] APP_ENV=production"

(new SecretScrubber)->scrub('connecting to postgres://app:s3cr3t@db:5432/app');
// "connecting to postgres://app:[redacted]@db:5432/app"
```

Several detectors keep their surrounding context on purpose. Knowing *which*
credential leaked, and where it pointed, is most of the value of the log line —
`APP_ENV=production` is untouched.

### Detectors

| Type | Matches |
|------|---------|
| `private_key` | PEM blocks of any key type, including the armour |
| `url_credentials` | The password in `scheme://user:pass@host` |
| `jwt` | Three-segment JSON Web Tokens |
| `aws_access_key_id` | `AKIA`/`ASIA`/`AGPA`/`AIDA`/`AROA`/`ANPA`/`ANVA` + 16 chars |
| `authorization` | The token after `Bearer` / `Basic` |
| `assignment` | Values of sensitively-named keys (`SECRET_KEY=…`, `"api_token": …`) |

Detection is best-effort — it cannot recognise a secret with no distinctive
shape and no telling name. Pair it with `LiteralScrubber` when you hold the
values.

`detect()`, `types()` and the `strategy` / `types` constructor arguments work
exactly as they do on `PiiScrubber`.

## Scrubbing known values

`LiteralScrubber` masks exact values you already hold — a resolved token, an
injected password, an API key from config. An exact match is certain where a
pattern is a guess.

```php
use CleaniqueCoders\PiiProtection\Detection\LiteralScrubber;

(new LiteralScrubber)->scrub('token abc123xyz here', ['abc123xyz']);
// "token [redacted] here"
```

### The three safety rules

None of these are obvious until the output is wrong:

- **Longest first.** A short value nested inside a longer one is masked second,
  so it cannot corrupt the longer one and leave part of it exposed.
- **Minimum length** (default 6). Blanking every occurrence of a 4-character
  value shreds unrelated text.
- **Skip pure digits.** A port, a replica count and a timeout are not secrets,
  and masking them everywhere destroys the log.

```php
new LiteralScrubber(minLength: 8, skipNumeric: false);
```

`prepare()` returns the values that survived those rules, so you can see why
something you passed was skipped rather than concluding the scrubber is broken:

```php
(new LiteralScrubber)->prepare(['short', '5432', null, 'long-enough-value']);
// ['long-enough-value']
```

`detect()` reports value and offset for each occurrence without modifying the
text.

## Tokenization

`Tokenizer` swaps a PII value for an opaque, random token (`tok_…`) and stores
the mapping in a `Vault`. The token reveals nothing about the value; only a
holder of the vault can reverse it.

```php
use CleaniqueCoders\PiiProtection\Tokenization\Tokenizer;
use CleaniqueCoders\PiiProtection\Tokenization\ArrayVault;

$tokenizer = new Tokenizer(new ArrayVault);

$token = $tokenizer->tokenize('012345678'); // "tok_9f3a…"
$tokenizer->detokenize($token);             // "012345678"
$tokenizer->forget($token);                 // drop the mapping
$tokenizer->detokenize($token);             // null
```

Each call to `tokenize()` produces a unique token, even for the same value.

### Persisting tokens

`ArrayVault` is in-memory and lives for a single process. To persist tokens
across requests, implement the [`Vault`](../01-architecture/02-contracts.md#vault)
contract over your cache or database:

```php
use CleaniqueCoders\PiiProtection\Contracts\Vault;

final class CacheVault implements Vault
{
    public function put(string $token, string $value): void { /* … */ }
    public function get(string $token): ?string { /* … */ }
    public function has(string $token): bool { /* … */ }
    public function forget(string $token): void { /* … */ }
}
```

## Next Steps

- [Masking](02-masking.md)
- [API Reference](../04-api/README.md)
