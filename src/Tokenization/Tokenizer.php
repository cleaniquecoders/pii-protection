<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Tokenization;

use CleaniqueCoders\PiiProtection\Contracts\Vault;
use CleaniqueCoders\PiiProtection\Exceptions\PiiException;

/**
 * Replaces a PII value with an opaque, random token and stores the mapping in
 * a {@see Vault}. The token reveals nothing about the value; only a holder of
 * the vault can reverse it.
 */
final class Tokenizer
{
    private const PREFIX = 'tok_';

    /**
     * @param  positive-int  $tokenBytes
     */
    public function __construct(
        private Vault $vault,
        private int $tokenBytes = 16,
    ) {
        if ($this->tokenBytes < 1) {
            throw new PiiException('Token length must be at least 1 byte.');
        }
    }

    public function tokenize(string $value): string
    {
        $token = self::PREFIX.bin2hex(random_bytes($this->tokenBytes));

        $this->vault->put($token, $value);

        return $token;
    }

    public function detokenize(string $token): ?string
    {
        return $this->vault->get($token);
    }

    public function forget(string $token): void
    {
        $this->vault->forget($token);
    }
}
