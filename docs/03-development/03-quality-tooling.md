# Quality Tooling

The gates every change must clear, and the automation that enforces them.

## Static analysis — PHPStan

PHPStan runs at **level max** against `src/`, configured in `phpstan.neon.dist`.

```bash
composer analyse
```

The bar is "no errors". Fix the underlying type issue rather than suppressing it
— avoid `@phpstan-ignore`, baseline entries, `assert()`, inline `@var`
overrides, and type casts added only to silence a finding.

## Code style — Pint

[Laravel Pint](https://laravel.com/docs/pint) enforces a consistent style.

```bash
composer format        # apply fixes
vendor/bin/pint --test # check only (used in CI/local verification)
```

A `fix-php-code-style-issues` GitHub workflow auto-commits Pint fixes on push.

## Continuous integration

| Workflow | Trigger | What it runs |
|----------|---------|--------------|
| `run-tests.yml` | push / PR touching PHP, `phpunit.xml.dist`, `composer.json` | Pest on a matrix: Ubuntu + Windows × `prefer-lowest` / `prefer-stable` |
| `phpstan.yml` | push / PR touching PHP, `phpstan.neon.dist`, `composer.json` | PHPStan level max |
| `fix-php-code-style-issues.yml` | push | Pint, auto-commit |
| `update-changelog.yml` | release published | Prepend the release notes to `CHANGELOG.md` |
| `dependabot-auto-merge.yml` | Dependabot PRs | Auto-merge minor/patch bumps |

CI installs dependencies with `composer update` (no committed lock file) and runs
with `coverage: none`.

## Local pre-flight

Before pushing, run the same gates CI will:

```bash
composer format
composer analyse
vendor/bin/pest --ci
```

## Releasing

Releases stay in the **1.x** line and must remain backward compatible with the
existing ciphertext format.

1. Merge the feature work to `main` (CI green).
2. Tag the version **without a `v` prefix**: `git tag -a 1.4.0 -m "1.4.0"` and push.
3. Create a GitHub release whose **title is the bare version number** (e.g.
   `1.4.0`). The `update-changelog` workflow uses the release title as the
   `CHANGELOG.md` heading and the release body as the entry, then commits back to
   `main` — `git pull` afterwards.

> **Warning**: A release title like "1.4.0 — Some Name" becomes the literal
> changelog heading. Keep the title to the version number only.

## Next Steps

- [Testing](02-testing.md)
- [Architecture](../01-architecture/README.md)
