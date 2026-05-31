<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class EmailStrategy implements MaskStrategy
{
    public function __construct(private string $maskedLocal = '****') {}

    public function mask(string $value): string
    {
        $position = mb_strrpos($value, '@');

        if ($position === false) {
            return str_repeat('*', mb_strlen($value));
        }

        return $this->maskedLocal.mb_substr($value, $position);
    }
}
