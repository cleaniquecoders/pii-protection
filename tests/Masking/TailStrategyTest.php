<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

it('keeps the last N characters and masks the rest', function () {
    expect((new TailStrategy(visible: 4))->mask('0123456789'))->toBe('******6789');
});

it('masks everything when the value is shorter than or equal to visible', function (string $value) {
    expect((new TailStrategy(visible: 4))->mask($value))
        ->toBe(str_repeat('*', mb_strlen($value)));
})->with([
    'shorter' => 'abc',
    'equal' => 'abcd',
]);

it('masks an empty string to an empty string', function () {
    expect((new TailStrategy)->mask(''))->toBe('');
});

it('is multibyte safe', function () {
    // 6 multibyte chars, keep last 2.
    expect((new TailStrategy(visible: 2))->mask('hélløwörld'))
        ->toBe('********ld');
});

it('defaults to 4 visible characters', function () {
    expect((new TailStrategy)->mask('0123456789'))->toBe('******6789');
});
