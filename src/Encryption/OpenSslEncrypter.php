<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Encryption;

use CleaniqueCoders\PiiProtection\Contracts\Encrypter;
use CleaniqueCoders\PiiProtection\Exceptions\DecryptionException;
use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

final class OpenSslEncrypter implements Encrypter
{
    private const CIPHER = 'aes-256-gcm';

    private const TAG_LENGTH = 16;

    /**
     * Raw 32-byte (256-bit) key derived from the injected key material.
     */
    private string $key;

    public function __construct(#[\SensitiveParameter] string $key)
    {
        if ($key === '') {
            throw EncryptionException::emptyKey();
        }

        // Normalise arbitrary key material to a raw 256-bit key.
        $this->key = hash('sha256', $key, true);
    }

    public function encrypt(string $plain): string
    {
        $ivLength = openssl_cipher_iv_length(self::CIPHER);

        if ($ivLength < 1) {
            throw EncryptionException::failed();
        }

        $iv = random_bytes($ivLength);
        $tag = '';

        $cipher = openssl_encrypt(
            $plain,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH,
        );

        if ($cipher === false) {
            throw EncryptionException::failed();
        }

        return base64_encode($iv.$tag.$cipher);
    }

    public function decrypt(string $cipher): string
    {
        $decoded = base64_decode($cipher, true);

        if ($decoded === false) {
            throw DecryptionException::notBase64();
        }

        $ivLength = (int) openssl_cipher_iv_length(self::CIPHER);
        $minLength = $ivLength + self::TAG_LENGTH;

        if (strlen($decoded) < $minLength) {
            throw DecryptionException::tooShort();
        }

        $iv = substr($decoded, 0, $ivLength);
        $tag = substr($decoded, $ivLength, self::TAG_LENGTH);
        $payload = substr($decoded, $minLength);

        $plain = openssl_decrypt(
            $payload,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($plain === false) {
            throw DecryptionException::failed();
        }

        return $plain;
    }
}
