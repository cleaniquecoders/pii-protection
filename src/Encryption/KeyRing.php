<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Encryption;

use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

/**
 * Holds one or more keyed encryption secrets so keys can be rotated without
 * re-encrypting everything at once: new ciphertext is written with the current
 * key, while older ciphertext is decrypted with whichever key its id points to.
 */
final class KeyRing
{
    /**
     * @var array<string,string> keyId => key material
     */
    private array $keys;

    private string $currentId;

    private string $legacyId;

    /**
     * @param  array<string,string>  $keys  keyId => key material (id must match [A-Za-z0-9_-]+)
     * @param  string|null  $currentId  the key used for new encryption (defaults to the first)
     * @param  string|null  $legacyId  the key that decrypts pre-1.2 unversioned ciphertext (defaults to currentId)
     */
    public function __construct(array $keys, ?string $currentId = null, ?string $legacyId = null)
    {
        if ($keys === []) {
            throw new EncryptionException('KeyRing requires at least one key.');
        }

        foreach ($keys as $id => $key) {
            if (! is_string($id) || preg_match('/^[A-Za-z0-9_-]+$/', $id) !== 1) {
                throw new EncryptionException('KeyRing key ids must match [A-Za-z0-9_-]+.');
            }

            if ($key === '') {
                throw new EncryptionException('KeyRing key material must not be empty.');
            }
        }

        $this->keys = $keys;
        $this->currentId = $currentId ?? array_key_first($keys);

        if (! isset($this->keys[$this->currentId])) {
            throw new EncryptionException("Unknown current key id: {$this->currentId}.");
        }

        $this->legacyId = $legacyId ?? $this->currentId;

        if (! isset($this->keys[$this->legacyId])) {
            throw new EncryptionException("Unknown legacy key id: {$this->legacyId}.");
        }
    }

    /**
     * Build a single-key ring (the common, non-rotating case).
     */
    public static function single(#[\SensitiveParameter] string $key, string $id = 'default'): self
    {
        return new self([$id => $key]);
    }

    public function currentId(): string
    {
        return $this->currentId;
    }

    public function currentKey(): string
    {
        return $this->keys[$this->currentId];
    }

    public function legacyKey(): string
    {
        return $this->keys[$this->legacyId];
    }

    public function get(string $id): string
    {
        if (! isset($this->keys[$id])) {
            throw new EncryptionException("Unknown key id: {$id}.");
        }

        return $this->keys[$id];
    }
}
