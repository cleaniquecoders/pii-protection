<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

interface Redactor
{
    /**
     * @param  array<array-key,mixed>  $data
     * @param  array<int|string,string|MaskStrategy>  $fields
     * @return array<array-key,mixed>
     */
    public function redact(array $data, array $fields): array;
}
