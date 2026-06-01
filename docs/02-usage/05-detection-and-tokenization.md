# Detection & Tokenization

Two capabilities for data that does not arrive as neat named fields: scrubbing
PII out of free text, and replacing values with opaque tokens.

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
