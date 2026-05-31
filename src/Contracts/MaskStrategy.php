<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

interface MaskStrategy
{
    public function mask(string $value): string;
}
