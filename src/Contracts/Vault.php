<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

/**
 * Stores the mapping between a token and its original value. Implementations
 * decide where that lives (memory, cache, database) — the package ships an
 * in-memory ArrayVault and never persists anything on your behalf.
 */
interface Vault
{
    public function put(string $token, string $value): void;

    public function get(string $token): ?string;

    public function has(string $token): bool;

    public function forget(string $token): void;
}
