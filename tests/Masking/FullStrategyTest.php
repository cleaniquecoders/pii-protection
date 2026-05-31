<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\FullStrategy;

it('masks every character', function () {
    expect((new FullStrategy)->mask('012345678'))->toBe('*********');
});

it('masks an empty string to an empty string', function () {
    expect((new FullStrategy)->mask(''))->toBe('');
});

it('is multibyte safe', function () {
    expect((new FullStrategy)->mask('héllo'))->toBe('*****');
});
