<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

interface Encrypter
{
    public function encrypt(string $plain): string;

    public function decrypt(string $cipher): string;
}
