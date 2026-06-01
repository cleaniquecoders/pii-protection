<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Exceptions;

final class EncryptionException extends PiiException
{
    public static function emptyKey(): self
    {
        return new self('Encryption key must not be empty.');
    }

    public static function failed(): self
    {
        return new self('Encryption failed.');
    }
}
