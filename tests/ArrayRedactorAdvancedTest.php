<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\ArrayRedactor;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\HashStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

it('applies a per-field strategy map', function () {
    $redactor = new ArrayRedactor(new TailStrategy(visible: 4));

    $clean = $redactor->redact([
        'email' => 'john.doe@acme.com',
        'phone' => '0123456789',
        'nric' => '900101011234',
    ], [
        'email' => new EmailStrategy,
        'phone' => new TailStrategy(visible: 4),
        'nric' => new HashStrategy,
    ]);

    expect($clean['email'])->toBe('****@acme.com')
        ->and($clean['phone'])->toBe('******6789')
        ->and($clean['nric'])->toBe(hash('sha256', '900101011234'));
});

it('mixes plain field names (default strategy) with a strategy map', function () {
    $redactor = new ArrayRedactor(new FullStrategy);

    $clean = $redactor->redact([
        'phone' => '0123456789',
        'email' => 'john@acme.com',
    ], [
        'phone',                       // default strategy (FullStrategy)
        'email' => new EmailStrategy,  // mapped strategy
    ]);

    expect($clean['phone'])->toBe('**********')
        ->and($clean['email'])->toBe('****@acme.com');
});

it('masks a value by dot-path only at that path', function () {
    $redactor = new ArrayRedactor(new TailStrategy(visible: 4));

    $clean = $redactor->redact([
        'user' => ['phone' => '0123456789'],
        'phone' => '0199999999', // top-level phone must stay untouched
    ], ['user.phone']);

    expect($clean['user']['phone'])->toBe('******6789')
        ->and($clean['phone'])->toBe('0199999999');
});

it('masks across a wildcard path segment', function () {
    $redactor = new ArrayRedactor(new TailStrategy(visible: 4));

    $clean = $redactor->redact([
        'users' => [
            ['phone' => '0123456789'],
            ['phone' => '0199999999'],
        ],
    ], ['users.*.phone']);

    expect($clean['users'][0]['phone'])->toBe('******6789')
        ->and($clean['users'][1]['phone'])->toBe('******9999');
});

it('supports a strategy-mapped dot-path', function () {
    $redactor = new ArrayRedactor(new TailStrategy(visible: 4));

    $clean = $redactor->redact([
        'contact' => ['email' => 'john@acme.com'],
    ], ['contact.email' => new EmailStrategy]);

    expect($clean['contact']['email'])->toBe('****@acme.com');
});

it('still supports the original list-of-names form', function () {
    $redactor = new ArrayRedactor(new TailStrategy(visible: 4));

    $clean = $redactor->redact([
        'phone' => '0123456789',
        'name' => 'Jane',
    ], ['phone']);

    expect($clean)->toBe(['phone' => '******6789', 'name' => 'Jane']);
});
