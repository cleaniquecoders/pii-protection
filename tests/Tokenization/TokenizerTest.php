<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Exceptions\PiiException;
use CleaniqueCoders\PiiProtection\Tokenization\ArrayVault;
use CleaniqueCoders\PiiProtection\Tokenization\Tokenizer;

it('tokenizes and detokenizes a value', function () {
    $tokenizer = new Tokenizer(new ArrayVault);

    $token = $tokenizer->tokenize('012345678');

    expect($token)->toStartWith('tok_')
        ->and($token)->not->toContain('012345678')
        ->and($tokenizer->detokenize($token))->toBe('012345678');
});

it('produces a unique token per call', function () {
    $tokenizer = new Tokenizer(new ArrayVault);

    expect($tokenizer->tokenize('same'))->not->toBe($tokenizer->tokenize('same'));
});

it('returns null when detokenizing an unknown token', function () {
    expect((new Tokenizer(new ArrayVault))->detokenize('tok_unknown'))->toBeNull();
});

it('forgets a token', function () {
    $tokenizer = new Tokenizer($vault = new ArrayVault);
    $token = $tokenizer->tokenize('x');

    $tokenizer->forget($token);

    expect($tokenizer->detokenize($token))->toBeNull()
        ->and($vault->has($token))->toBeFalse();
});

it('rejects an invalid token length', function () {
    expect(fn () => new Tokenizer(new ArrayVault, tokenBytes: 0))->toThrow(PiiException::class);
});

it('stores and reads through the vault contract', function () {
    $vault = new ArrayVault;
    $vault->put('tok_a', 'value-a');

    expect($vault->has('tok_a'))->toBeTrue()
        ->and($vault->get('tok_a'))->toBe('value-a')
        ->and($vault->get('tok_missing'))->toBeNull();
});
