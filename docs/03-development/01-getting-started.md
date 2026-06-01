# Getting Started

Set up a local environment to work on the package.

## Prerequisites

- PHP `^8.4` with `ext-openssl` and `ext-mbstring`
- Composer
- A coverage driver (Xdebug or PCOV) — required only for coverage and mutation
  testing

## Clone and install

```bash
git clone https://github.com/cleaniquecoders/pii-protection.git
cd pii-protection
composer install
```

> **Note**: `composer.lock` is intentionally not committed (this is a library),
> so CI resolves dependencies fresh with `composer update`.

## Verify your setup

```bash
composer test      # run the Pest suite
composer analyse   # run PHPStan at level max
composer format    # apply Pint code style
```

All three should pass on a clean checkout. If `composer test` reports
*"No code coverage driver available"* and exits, that is expected only when a
`<coverage>` report is configured without a driver — the project's
`phpunit.xml.dist` deliberately omits report config so tests run without one.

## Project layout

| Path | Contents |
|------|----------|
| `src/` | Library source (PSR-4: `CleaniqueCoders\PiiProtection\`) |
| `tests/` | Pest tests (`CleaniqueCoders\PiiProtection\Tests\`) |
| `phpstan.neon.dist` | PHPStan config (level max, analyses `src`) |
| `.github/workflows/` | CI: `run-tests.yml`, `phpstan.yml`, and style/changelog automation |

## Next Steps

- [Testing](02-testing.md)
- [Quality Tooling](03-quality-tooling.md)
