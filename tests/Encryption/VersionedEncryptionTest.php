<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Exceptions\DecryptionException;

/**
 * Build a pre-1.2 (v1) ciphertext exactly as 1.0/1.1 produced it:
 * base64(iv || tag || ciphertext) with key = sha256(material).
 */
function makeLegacyCipher(string $material, string $plain): string
{
    $key = hash('sha256', $material, true);
    $ivLength = (int) openssl_cipher_iv_length('aes-256-gcm');
    $iv = random_bytes($ivLength);
    $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

    return base64_encode($iv.$tag.(string) $ct);
}

it('writes versioned (v2) ciphertext', function () {
    $cipher = (new OpenSslEncrypter(key: 'secret'))->encrypt('012345678');

    expect($cipher)->toStartWith('v2.default.');
});

it('round-trips versioned ciphertext', function () {
    $enc = new OpenSslEncrypter(key: 'secret');

    expect($enc->decrypt($enc->encrypt('012345678')))->toBe('012345678');
});

it('produces different ciphertext across calls (random salt + iv)', function () {
    $enc = new OpenSslEncrypter(key: 'secret');

    expect($enc->encrypt('012345678'))->not->toBe($enc->encrypt('012345678'));
});

it('decrypts legacy v1 ciphertext (backward compatible)', function () {
    $legacy = makeLegacyCipher('secret', '012345678');

    expect((new OpenSslEncrypter(key: 'secret'))->decrypt($legacy))->toBe('012345678');
});

it('binds ciphertext to a context (AAD)', function () {
    $enc = new OpenSslEncrypter(key: 'secret');

    $cipher = $enc->encryptWithContext('012345678', 'user:123');

    expect($enc->decryptWithContext($cipher, 'user:123'))->toBe('012345678');
});

it('fails to decrypt when the context differs', function () {
    $enc = new OpenSslEncrypter(key: 'secret');
    $cipher = $enc->encryptWithContext('012345678', 'user:123');

    expect(fn () => $enc->decryptWithContext($cipher, 'user:999'))
        ->toThrow(DecryptionException::class);
});

it('treats encrypt() as an empty context', function () {
    $enc = new OpenSslEncrypter(key: 'secret');

    expect($enc->decryptWithContext($enc->encrypt('hi'), ''))->toBe('hi');
});
