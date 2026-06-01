<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

it('uses a custom mask character in TailStrategy', function () {
    expect((new TailStrategy(visible: 4, maskChar: '•'))->mask('0123456789'))
        ->toBe('••••••6789');
});

it('uses a custom mask character in FullStrategy', function () {
    expect((new FullStrategy(maskChar: 'x'))->mask('abc'))->toBe('xxx');
});

it('uses a custom mask character in EmailStrategy fallback', function () {
    expect((new EmailStrategy(maskChar: '#'))->mask('not-an-email'))
        ->toBe('############');
});

it('defaults the mask character to *', function () {
    expect((new TailStrategy)->mask('0123456789'))->toBe('******6789')
        ->and((new FullStrategy)->mask('abc'))->toBe('***');
});
