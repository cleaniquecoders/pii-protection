<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Exceptions\DecryptionException;
use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;
use CleaniqueCoders\PiiProtection\Exceptions\PiiException;

it('throws EncryptionException on an empty key', function () {
    expect(fn () => new OpenSslEncrypter(key: ''))->toThrow(EncryptionException::class);
});

it('throws DecryptionException on non-base64 ciphertext', function () {
    expect(fn () => (new OpenSslEncrypter(key: 'k'))->decrypt('!!!'))
        ->toThrow(DecryptionException::class);
});

it('throws DecryptionException on a tampered/short payload', function () {
    expect(fn () => (new OpenSslEncrypter(key: 'k'))->decrypt(base64_encode('short')))
        ->toThrow(DecryptionException::class);
});

it('exposes a common PiiException base type', function () {
    expect(fn () => new OpenSslEncrypter(key: ''))->toThrow(PiiException::class);
});

it('keeps RuntimeException compatibility', function () {
    expect(fn () => new OpenSslEncrypter(key: ''))->toThrow(RuntimeException::class);
});
