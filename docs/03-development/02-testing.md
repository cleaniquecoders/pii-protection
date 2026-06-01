# Testing

The package is tested with [Pest](https://pestphp.com). Tests are plain Pest —
no framework harness is needed.

## Running tests

```bash
composer test                 # full suite
vendor/bin/pest --ci          # CI mode (used by GitHub Actions)
vendor/bin/pest tests/Masking # a single directory
```

## What the suite covers

| Area | Focus |
|------|-------|
| Masking | Empty string, `length <= visible`, multibyte, email shapes, per-strategy edge cases |
| Encryption | Round-trip, ciphertext differs across calls, tamper rejection, wrong key/context |
| Backward compatibility | A hand-built v1 ciphertext is decrypted by the current code |
| Key rotation | Encrypt under one key id, decrypt after rotating, legacy-key fallback |
| Blind index | Determinism, constant-time match, truncation, normaliser |
| Redaction | Flat / nested / JSON payloads, per-field maps, dot-path & wildcards, `#[Pii]` objects |
| Detection & tokenization | Scrub/detect patterns, token round-trip, vault contract |
| Architecture | No debugging functions (`dd`, `dump`, `ray`) left in the code |

## Mutation testing

Mutation testing uses Pest's native mutation engine (it requires a coverage
driver):

```bash
composer test-mutate
```

This mutates `src/` and re-runs the covered tests to confirm they actually fail
when the code is broken. Aim to keep the score high; investigate any escaped
mutants.

> **Tip**: Run a focused mutation pass while iterating, e.g.
> `vendor/bin/pest --mutate --covered-only --class="CleaniqueCoders\\PiiProtection\\Masking\\TailStrategy"`.

## Writing tests

Match the existing style: small, table-driven `it(...)` blocks with clear
expectations. When adding a feature, cover the happy path, the edge cases, and —
for anything touching ciphertext — backward compatibility with the existing
format.

## Next Steps

- [Quality Tooling](03-quality-tooling.md)
