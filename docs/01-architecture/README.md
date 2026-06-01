# Architecture

How the package is put together — the primitives, the contracts that decouple
consumers from implementations, and the rationale behind the key design
choices.

## Table of Contents

### [1. Overview](01-overview.md)

The primitives at a glance, the package layout, and how the pieces fit
together.

### [2. Contracts](02-contracts.md)

The interfaces consumers depend on: `Encrypter`, `ContextualEncrypter`,
`MaskStrategy`, `Redactor`, and `Vault`.

### [3. Design Decisions](03-design-decisions.md)

Why AES-256-GCM with HKDF, the versioned ciphertext format and its
backward-compatibility guarantee, and the "never query an encrypted column"
guardrail.

## Related Documentation

- [Usage](../02-usage/README.md) — apply these building blocks to real tasks.
- [API Reference](../04-api/README.md) — the full surface of every class.
