<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Encryption;

use CleaniqueCoders\PiiProtection\Contracts\Encrypter;
use RuntimeException;

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
            throw new RuntimeException('Encryption key must not be empty.');
        }

        // Normalise arbitrary key material to a raw 256-bit key.
        $this->key = hash('sha256', $key, true);
    }

    public function encrypt(string $plain): string
    {
        $ivLength = (int) openssl_cipher_iv_length(self::CIPHER);
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
            throw new RuntimeException('Encryption failed.');
        }

        return base64_encode($iv.$tag.$cipher);
    }

    public function decrypt(string $cipher): string
    {
        $decoded = base64_decode($cipher, true);

        if ($decoded === false) {
            throw new RuntimeException('Invalid ciphertext: not valid base64.');
        }

        $ivLength = (int) openssl_cipher_iv_length(self::CIPHER);
        $minLength = $ivLength + self::TAG_LENGTH;

        if (strlen($decoded) < $minLength) {
            throw new RuntimeException('Invalid ciphertext: payload too short.');
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
            throw new RuntimeException('Decryption failed: ciphertext may be tampered or the key is wrong.');
        }

        return $plain;
    }
}
