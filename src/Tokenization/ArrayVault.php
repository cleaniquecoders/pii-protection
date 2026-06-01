<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Tokenization;

use CleaniqueCoders\PiiProtection\Contracts\Vault;

/**
 * In-memory token vault. Suitable for a single request/process; swap in your
 * own Vault implementation to persist tokens across requests.
 */
final class ArrayVault implements Vault
{
    /**
     * @var array<string,string>
     */
    private array $store = [];

    public function put(string $token, string $value): void
    {
        $this->store[$token] = $value;
    }

    public function get(string $token): ?string
    {
        return $this->store[$token] ?? null;
    }

    public function has(string $token): bool
    {
        return isset($this->store[$token]);
    }

    public function forget(string $token): void
    {
        unset($this->store[$token]);
    }
}
