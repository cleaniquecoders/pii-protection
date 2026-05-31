<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class HashStrategy implements MaskStrategy
{
    public function __construct(private string $algo = 'sha256') {}

    public function mask(string $value): string
    {
        return hash($this->algo, $value);
    }
}
