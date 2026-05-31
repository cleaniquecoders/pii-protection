<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;

it('masks the local part and keeps the domain', function (string $email, string $expected) {
    expect((new EmailStrategy)->mask($email))->toBe($expected);
})->with([
    'simple' => ['john@acme.com', '****@acme.com'],
    'dotted local' => ['john.doe@acme.com', '****@acme.com'],
    'plus tag' => ['john+news@acme.com', '****@acme.com'],
    'subdomain' => ['john@mail.acme.co.uk', '****@mail.acme.co.uk'],
]);

it('full-masks a value without an @', function () {
    expect((new EmailStrategy)->mask('not-an-email'))->toBe('************');
});

it('uses the last @ to split local and domain', function () {
    expect((new EmailStrategy)->mask('weird@local@acme.com'))->toBe('****@acme.com');
});

it('allows a custom masked local part', function () {
    expect((new EmailStrategy(maskedLocal: '***'))->mask('john@acme.com'))->toBe('***@acme.com');
});
