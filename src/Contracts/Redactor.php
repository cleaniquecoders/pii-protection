<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

interface Redactor
{
    /**
     * @param  array<string,mixed>  $data
     * @param  array<int,string>  $fields
     * @return array<string,mixed>
     */
    public function redact(array $data, array $fields): array;
}
