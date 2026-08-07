<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\RedactedStrategy;

it('replaces the value with a fixed placeholder', function () {
    expect((new RedactedStrategy)->mask('hunter2'))->toBe('[redacted]');
});

it('accepts a custom placeholder', function () {
    expect((new RedactedStrategy('***REMOVED***'))->mask('hunter2'))->toBe('***REMOVED***');
});

it('reveals nothing about the length of the secret', function () {
    $strategy = new RedactedStrategy;

    $short = $strategy->mask('abcdef');
    $long = $strategy->mask(str_repeat('x', 64));

    // The whole point of this strategy: FullStrategy would emit 6 and 64
    // asterisks, telling an attacker which credential they are looking at.
    expect($short)->toBe($long)
        ->and((new FullStrategy)->mask('abcdef'))
        ->not->toBe((new FullStrategy)->mask(str_repeat('x', 64)));
});

it('masks an empty string to the placeholder', function () {
    expect((new RedactedStrategy)->mask(''))->toBe('[redacted]');
});
