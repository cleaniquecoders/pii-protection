<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Encryption;

use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

/**
 * Deterministic HMAC-SHA256 blind index for searchable PII.
 *
 * Store the reversible ciphertext (via {@see OpenSslEncrypter}) in one column
 * and this blind index in another; query the blind index for equality lookups
 * without ever decrypting. The index is one-way — it cannot reveal the value,
 * only confirm a match.
 *
 * An optional normaliser (e.g. lowercase + trim) makes lookups case- or
 * whitespace-insensitive; apply the SAME normaliser at write and query time.
 */
final class HmacBlindIndex
{
    private string $key;

    private int $length;

    /** @var (callable(string): string)|null */
    private $normaliser;

    /**
     * @param  int  $length  number of hex characters to keep (1–64); shorter trades collision-resistance for storage
     * @param  (callable(string): string)|null  $normaliser  applied to the value before hashing
     */
    public function __construct(
        #[\SensitiveParameter] string $key,
        int $length = 64,
        ?callable $normaliser = null,
    ) {
        if ($key === '') {
            throw new EncryptionException('Blind index key must not be empty.');
        }

        if ($length < 1 || $length > 64) {
            throw new EncryptionException('Blind index length must be between 1 and 64.');
        }

        $this->key = $key;
        $this->length = $length;
        $this->normaliser = $normaliser;
    }

    public function index(string $value): string
    {
        if ($this->normaliser !== null) {
            $value = ($this->normaliser)($value);
        }

        return substr(hash_hmac('sha256', $value, $this->key), 0, $this->length);
    }

    /**
     * Constant-time comparison of a value against a stored index.
     */
    public function matches(string $value, string $storedIndex): bool
    {
        return hash_equals($storedIndex, $this->index($value));
    }
}
