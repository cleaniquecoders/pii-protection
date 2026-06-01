<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class FullStrategy implements MaskStrategy
{
    public function __construct(private string $maskChar = '*') {}

    public function mask(string $value): string
    {
        return str_repeat($this->maskChar, mb_strlen($value));
    }
}
