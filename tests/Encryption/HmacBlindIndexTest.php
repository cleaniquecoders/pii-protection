<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\HmacBlindIndex;
use CleaniqueCoders\PiiProtection\Exceptions\EncryptionException;

it('is deterministic for the same value and key', function () {
    $index = new HmacBlindIndex(key: 'index-key');

    expect($index->index('user@acme.com'))->toBe($index->index('user@acme.com'));
});

it('produces different indexes for different values', function () {
    $index = new HmacBlindIndex(key: 'index-key');

    expect($index->index('a@acme.com'))->not->toBe($index->index('b@acme.com'));
});

it('produces different indexes under different keys', function () {
    expect((new HmacBlindIndex(key: 'k1'))->index('x'))
        ->not->toBe((new HmacBlindIndex(key: 'k2'))->index('x'));
});

it('matches a value against its stored index in constant time', function () {
    $index = new HmacBlindIndex(key: 'index-key');
    $stored = $index->index('012345678');

    expect($index->matches('012345678', $stored))->toBeTrue()
        ->and($index->matches('999999999', $stored))->toBeFalse();
});

it('truncates to the requested hex length', function () {
    expect(strlen((new HmacBlindIndex(key: 'k', length: 16))->index('x')))->toBe(16);
});

it('applies a normaliser for case-insensitive lookups', function () {
    $index = new HmacBlindIndex(key: 'k', normaliser: fn (string $v) => strtolower(trim($v)));

    expect($index->index('  USER@Acme.com '))->toBe($index->index('user@acme.com'));
});

it('rejects an empty key', function () {
    expect(fn () => new HmacBlindIndex(key: ''))->toThrow(EncryptionException::class);
});

it('rejects an out-of-range length', function () {
    expect(fn () => new HmacBlindIndex(key: 'k', length: 0))->toThrow(EncryptionException::class)
        ->and(fn () => new HmacBlindIndex(key: 'k', length: 65))->toThrow(EncryptionException::class);
});
