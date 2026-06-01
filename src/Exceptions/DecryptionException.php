<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Exceptions;

final class DecryptionException extends PiiException
{
    public static function notBase64(): self
    {
        return new self('Invalid ciphertext: not valid base64.');
    }

    public static function tooShort(): self
    {
        return new self('Invalid ciphertext: payload too short.');
    }

    public static function failed(): self
    {
        return new self('Decryption failed: ciphertext may be tampered or the key is wrong.');
    }
}
