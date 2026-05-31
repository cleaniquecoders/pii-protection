<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class FullStrategy implements MaskStrategy
{
    public function mask(string $value): string
    {
        return str_repeat('*', mb_strlen($value));
    }
}
