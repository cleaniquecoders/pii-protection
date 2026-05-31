<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;

it('round-trips encrypt then decrypt back to the original', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    $cipher = $encrypter->encrypt('012345678');

    expect($encrypter->decrypt($cipher))->toBe('012345678');
});

it('produces ciphertext that differs from the plaintext', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    expect($encrypter->encrypt('012345678'))->not->toBe('012345678');
});

it('produces different ciphertext across calls (random IV)', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    expect($encrypter->encrypt('012345678'))
        ->not->toBe($encrypter->encrypt('012345678'));
});

it('round-trips an empty string', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    expect($encrypter->decrypt($encrypter->encrypt('')))->toBe('');
});

it('round-trips multibyte content', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    $value = 'héllø wörld 你好';

    expect($encrypter->decrypt($encrypter->encrypt($value)))->toBe($value);
});

it('rejects tampered ciphertext', function () {
    $encrypter = new OpenSslEncrypter(key: 'super-secret-key');

    $cipher = $encrypter->encrypt('012345678');
    $tampered = base64_encode(base64_decode($cipher) ^ str_repeat("\xff", strlen(base64_decode($cipher))));

    expect(fn () => $encrypter->decrypt($tampered))->toThrow(RuntimeException::class);
});

it('fails to decrypt with the wrong key', function () {
    $cipher = (new OpenSslEncrypter(key: 'key-a'))->encrypt('012345678');

    expect(fn () => (new OpenSslEncrypter(key: 'key-b'))->decrypt($cipher))
        ->toThrow(RuntimeException::class);
});

it('rejects an empty key', function () {
    expect(fn () => new OpenSslEncrypter(key: ''))->toThrow(RuntimeException::class);
});

it('rejects non-base64 ciphertext', function () {
    expect(fn () => (new OpenSslEncrypter(key: 'k'))->decrypt('!!!not-base64!!!'))
        ->toThrow(RuntimeException::class);
});
