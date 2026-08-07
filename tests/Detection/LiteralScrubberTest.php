<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Detection\LiteralScrubber;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

it('masks a known value wherever it appears', function () {
    expect((new LiteralScrubber)->scrub('token abc123xyz and again abc123xyz', ['abc123xyz']))
        ->toBe('token [redacted] and again [redacted]');
});

it('masks several values in one pass', function () {
    $result = (new LiteralScrubber)->scrub(
        'user=alice-secret pass=bob-secret',
        ['alice-secret', 'bob-secret'],
    );

    expect($result)->toBe('user=[redacted] pass=[redacted]');
});

it('masks the longest value first so nested values cannot corrupt it', function () {
    // 'secret-value' contains 'secret'. Masking the short one first would
    // leave '[redacted]-value' — the longer secret partially exposed.
    expect((new LiteralScrubber)->scrub('the secret-value here', ['secret', 'secret-value']))
        ->toBe('the [redacted] here');
});

it('skips values shorter than the minimum length', function () {
    // Blanking every 'abc' would shred unrelated text.
    expect((new LiteralScrubber)->scrub('abc abcdef', ['abc']))->toBe('abc abcdef');
});

it('honours a custom minimum length', function () {
    expect((new LiteralScrubber(minLength: 3))->scrub('abc here', ['abc']))
        ->toBe('[redacted] here');
});

it('skips purely numeric values by default', function () {
    // A port, a replica count and a timeout are not secrets, and masking
    // them everywhere destroys the log.
    expect((new LiteralScrubber)->scrub('listening on 5432 with 5432 backlog', ['5432']))
        ->toBe('listening on 5432 with 5432 backlog');
});

it('can be told to mask numeric values', function () {
    expect((new LiteralScrubber(skipNumeric: false))->scrub('pin 123456 ok', ['123456']))
        ->toBe('pin [redacted] ok');
});

it('ignores null and empty values', function () {
    expect((new LiteralScrubber)->scrub('unchanged text', [null, '', '   ']))
        ->toBe('unchanged text');
});

it('trims surrounding whitespace before matching', function () {
    expect((new LiteralScrubber)->scrub('value abc123xyz end', ['  abc123xyz  ']))
        ->toBe('value [redacted] end');
});

it('de-duplicates repeated values', function () {
    expect((new LiteralScrubber)->prepare(['abc123xyz', 'abc123xyz']))
        ->toBe(['abc123xyz']);
});

it('returns the text unchanged when nothing survives preparation', function () {
    expect((new LiteralScrubber)->scrub('nothing to do', ['ab', '99', null]))
        ->toBe('nothing to do');
});

it('accepts a different mask strategy', function () {
    expect((new LiteralScrubber(new FullStrategy))->scrub('token abc123xyz', ['abc123xyz']))
        ->toBe('token *********');

    expect((new LiteralScrubber(new TailStrategy(visible: 4)))->scrub('token abc123xyz', ['abc123xyz']))
        ->toBe('token *****3xyz');
});

it('reports where each value appears without modifying the text', function () {
    $found = (new LiteralScrubber)->detect('abc123xyz then abc123xyz', ['abc123xyz']);

    expect($found)->toHaveCount(2)
        ->and($found[0])->toBe(['value' => 'abc123xyz', 'offset' => 0])
        ->and($found[1]['offset'])->toBe(15);
});

it('reports nothing when the value is absent', function () {
    expect((new LiteralScrubber)->detect('clean text', ['abc123xyz']))->toBe([]);
});

it('exposes which values would actually be used', function () {
    // So a caller can see why something it passed was skipped, rather than
    // concluding the scrubber is broken.
    expect((new LiteralScrubber)->prepare(['short', '5432', null, 'long-enough-value', 'abcdef']))
        ->toBe(['long-enough-value', 'abcdef']);
});

it('handles multibyte values', function () {
    expect((new LiteralScrubber)->scrub('kata laluan rahsia-besar di sini', ['rahsia-besar']))
        ->toBe('kata laluan [redacted] di sini');
});

it('handles an empty value list', function () {
    expect((new LiteralScrubber)->scrub('unchanged', []))->toBe('unchanged');
});
