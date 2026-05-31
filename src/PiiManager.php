<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection;

use CleaniqueCoders\PiiProtection\Contracts\Encrypter;
use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

final class PiiManager
{
    private ArrayRedactor $redactor;

    public function __construct(
        private Encrypter $encrypter,
        private MaskStrategy $strategy,
    ) {
        $this->redactor = new ArrayRedactor($strategy);
    }

    public function encrypt(string $plain): string
    {
        return $this->encrypter->encrypt($plain);
    }

    public function decrypt(string $cipher): string
    {
        return $this->encrypter->decrypt($cipher);
    }

    public function mask(string $value): string
    {
        return $this->strategy->mask($value);
    }

    /**
     * @param  array<string,mixed>  $data
     * @param  array<int,string>  $fields
     * @return array<string,mixed>
     */
    public function redact(array $data, array $fields): array
    {
        return $this->redactor->redact($data, $fields);
    }
}
