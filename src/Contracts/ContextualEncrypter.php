<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Contracts;

/**
 * An Encrypter that can bind ciphertext to a caller-supplied context using
 * AEAD additional-authenticated-data. The same context must be supplied on
 * decrypt or authentication fails.
 *
 * The base encrypt()/decrypt() methods are equivalent to using an empty
 * context, so this stays compatible with the {@see Encrypter} contract.
 */
interface ContextualEncrypter extends Encrypter
{
    public function encryptWithContext(string $plain, string $context): string;

    public function decryptWithContext(string $cipher, string $context): string;
}
