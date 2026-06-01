<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\KeyRing;
use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

it('encrypts with the current key id', function () {
    $ring = new KeyRing(['k1' => 'secret-one', 'k2' => 'secret-two'], currentId: 'k2');

    expect((new OpenSslEncrypter($ring))->encrypt('x'))->toStartWith('v2.k2.');
});

it('decrypts ciphertext written under a rotated-out key', function () {
    // Old data encrypted while k1 was current.
    $old = new OpenSslEncrypter(new KeyRing(['k1' => 'secret-one'], currentId: 'k1'));
    $cipher = $old->encrypt('012345678');

    // After rotation: k2 is current, but k1 is still on the ring.
    $rotated = new OpenSslEncrypter(new KeyRing(
        ['k1' => 'secret-one', 'k2' => 'secret-two'],
        currentId: 'k2',
    ));

    expect($rotated->decrypt($cipher))->toBe('012345678')
        ->and($rotated->encrypt('new'))->toStartWith('v2.k2.');
});

it('throws when the ciphertext key id is not on the ring', function () {
    $cipher = (new OpenSslEncrypter(new KeyRing(['k1' => 'secret-one'])))->encrypt('x');

    $other = new OpenSslEncrypter(new KeyRing(['k9' => 'secret-nine']));

    expect(fn () => $other->decrypt($cipher))->toThrow(EncryptionException::class);
});

it('decrypts legacy ciphertext using the designated legacy key', function () {
    // Legacy v1 cipher made with the original material "secret-one".
    $key = hash('sha256', 'secret-one', true);
    $iv = random_bytes((int) openssl_cipher_iv_length('aes-256-gcm'));
    $tag = '';
    $ct = openssl_encrypt('012345678', 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    $legacy = base64_encode($iv.$tag.(string) $ct);

    $ring = new KeyRing(
        ['k1' => 'secret-one', 'k2' => 'secret-two'],
        currentId: 'k2',
        legacyId: 'k1',
    );

    expect((new OpenSslEncrypter($ring))->decrypt($legacy))->toBe('012345678');
});

it('rejects an empty ring', function () {
    expect(fn () => new KeyRing([]))->toThrow(EncryptionException::class);
});

it('rejects invalid key ids', function () {
    expect(fn () => new KeyRing(['bad.id' => 'secret']))->toThrow(EncryptionException::class);
});

it('rejects an unknown current id', function () {
    expect(fn () => new KeyRing(['k1' => 'secret'], currentId: 'nope'))
        ->toThrow(EncryptionException::class);
});
