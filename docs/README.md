# Documentation

Welcome to the documentation for **`cleaniquecoders/pii-protection`** — pure-PHP,
framework-agnostic primitives for protecting personally identifiable information
(PII): field-level encryption at rest, masking, redaction, detection, and
tokenization.

Everything is constructor-injected and contract-based, with zero framework
dependencies, so it drops into Laravel, Symfony, Slim, a CLI tool, a queue
worker, or plain PHP unchanged.

## Documentation Structure

### [01. Architecture](01-architecture/README.md)

The building blocks, the contracts consumers depend on, and the design
decisions behind the encryption format, masking, and redaction.

### [02. Usage](02-usage/README.md)

Practical, task-oriented guides: installation, masking strategies, encryption
and key rotation, payload/object redaction, free-text detection, and
tokenization.

### [03. Development](03-development/README.md)

Working on the package itself: running the test suite, static analysis,
mutation testing, and the release workflow.

### [04. API Reference](04-api/README.md)

A compact reference of every public class, contract, and method.

## Quick Start

New here? Start with [Getting Started](02-usage/01-getting-started.md), then skim
the [Architecture Overview](01-architecture/01-overview.md).

## Finding Information

- **Concepts & design** — see [Architecture](01-architecture/README.md).
- **How do I…?** — see [Usage](02-usage/README.md).
- **Class/method reference** — see [API Reference](04-api/README.md).
- **Contributing** — see [Development](03-development/README.md).
