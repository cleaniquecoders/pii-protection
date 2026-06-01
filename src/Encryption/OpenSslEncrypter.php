<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Encryption;

use CleaniqueCoders\PiiProtection\Contracts\ContextualEncrypter;
use CleaniqueCoders\PiiProtection\Exceptions\DecryptionException;
use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

/**
 * AES-256-GCM encrypter.
 *
 * New ciphertext is written in a self-describing, versioned format:
 *
 *     v2.<keyId>.<base64( salt(16) || iv(12) || tag(16) || ciphertext )>
 *
 * with the data-encryption key derived per message via HKDF-SHA256 from the
 * ring key + random salt, and the caller context bound as GCM AAD.
 *
 * Ciphertext produced by 1.0/1.1 (unversioned `base64(iv||tag||ciphertext)`,
 * key = sha256(material)) still decrypts via the legacy path — the "v2."
 * prefix is unambiguous because "." is not a base64 character.
 */
final class OpenSslEncrypter implements ContextualEncrypter
{
    private const CIPHER = 'aes-256-gcm';

    private const TAG_LENGTH = 16;

    private const SALT_LENGTH = 16;

    private const VERSION = 'v2';

    private const HKDF_INFO = 'pii-protection/aes-256-gcm';

    private KeyRing $keys;

    public function __construct(#[\SensitiveParameter] string|KeyRing $key)
    {
        if (is_string($key)) {
            if ($key === '') {
                throw EncryptionException::emptyKey();
            }

            $key = KeyRing::single($key);
        }

        $this->keys = $key;
    }

    public function encrypt(string $plain): string
    {
        return $this->encryptWithContext($plain, '');
    }

    public function decrypt(string $cipher): string
    {
        return $this->decryptWithContext($cipher, '');
    }

    public function encryptWithContext(string $plain, string $context): string
    {
        $ivLength = openssl_cipher_iv_length(self::CIPHER);

        if ($ivLength < 1) {
            throw EncryptionException::failed();
        }

        $keyId = $this->keys->currentId();
        $salt = random_bytes(self::SALT_LENGTH);
        $iv = random_bytes($ivLength);
        $tag = '';

        $cipher = openssl_encrypt(
            $plain,
            self::CIPHER,
            $this->deriveKey($this->keys->currentKey(), $salt),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context,
            self::TAG_LENGTH,
        );

        if ($cipher === false) {
            throw EncryptionException::failed();
        }

        return self::VERSION.'.'.$keyId.'.'.base64_encode($salt.$iv.$tag.$cipher);
    }

    public function decryptWithContext(string $cipher, string $context): string
    {
        if (str_starts_with($cipher, self::VERSION.'.')) {
            return $this->decryptVersioned($cipher, $context);
        }

        return $this->decryptLegacy($cipher);
    }

    private function decryptVersioned(string $cipher, string $context): string
    {
        $parts = explode('.', $cipher, 3);

        if (count($parts) !== 3 || $parts[2] === '') {
            throw DecryptionException::tooShort();
        }

        $key = $this->keys->get($parts[1]);

        $decoded = base64_decode($parts[2], true);

        if ($decoded === false) {
            throw DecryptionException::notBase64();
        }

        $ivLength = (int) openssl_cipher_iv_length(self::CIPHER);
        $headerLength = self::SALT_LENGTH + $ivLength + self::TAG_LENGTH;

        if (strlen($decoded) < $headerLength) {
            throw DecryptionException::tooShort();
        }

        $salt = substr($decoded, 0, self::SALT_LENGTH);
        $iv = substr($decoded, self::SALT_LENGTH, $ivLength);
        $tag = substr($decoded, self::SALT_LENGTH + $ivLength, self::TAG_LENGTH);
        $payload = substr($decoded, $headerLength);

        $plain = openssl_decrypt(
            $payload,
            self::CIPHER,
            $this->deriveKey($key, $salt),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context,
        );

        if ($plain === false) {
            throw DecryptionException::failed();
        }

        return $plain;
    }

    private function decryptLegacy(string $cipher): string
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
            hash('sha256', $this->keys->legacyKey(), true),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
        );

        if ($plain === false) {
            throw DecryptionException::failed();
        }

        return $plain;
    }

    /**
     * Derive a per-message 256-bit data key via HKDF-SHA256.
     */
    private function deriveKey(string $keyMaterial, string $salt): string
    {
        return hash_hkdf('sha256', $keyMaterial, 32, self::HKDF_INFO, $salt);
    }
}
