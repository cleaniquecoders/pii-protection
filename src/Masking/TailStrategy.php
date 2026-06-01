<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class TailStrategy implements MaskStrategy
{
    public function __construct(
        private int $visible = 4,
        private string $maskChar = '*',
    ) {}

    public function mask(string $value): string
    {
        $length = mb_strlen($value);

        return $length > $this->visible
            ? str_repeat($this->maskChar, $length - $this->visible).mb_substr($value, -$this->visible)
            : str_repeat($this->maskChar, $length);
    }
}
