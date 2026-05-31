<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\HashStrategy;

it('produces a one-way sha256 digest', function () {
    expect((new HashStrategy)->mask('012345678'))
        ->toBe(hash('sha256', '012345678'));
});

it('is deterministic for the same input', function () {
    $strategy = new HashStrategy;

    expect($strategy->mask('secret'))->toBe($strategy->mask('secret'));
});

it('produces different digests for different input', function () {
    $strategy = new HashStrategy;

    expect($strategy->mask('a'))->not->toBe($strategy->mask('b'));
});

it('supports a custom algorithm', function () {
    expect((new HashStrategy(algo: 'sha512'))->mask('x'))
        ->toBe(hash('sha512', 'x'));
});
