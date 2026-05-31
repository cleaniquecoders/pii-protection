<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\ArrayRedactor;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

beforeEach(function () {
    $this->redactor = new ArrayRedactor(new TailStrategy(visible: 4));
});

it('masks listed fields and leaves the rest untouched on a flat payload', function () {
    $clean = $this->redactor->redact([
        'name' => 'Jane Doe',
        'phone' => '0123456789',
        'national_id' => '900101011234',
    ], ['phone', 'national_id']);

    expect($clean)->toBe([
        'name' => 'Jane Doe',
        'phone' => '******6789',
        'national_id' => '********1234',
    ]);
});

it('recurses into nested arrays', function () {
    $clean = $this->redactor->redact([
        'old_values' => ['phone' => '0123456789', 'name' => 'Jane'],
        'new_values' => ['phone' => '0199999999', 'name' => 'Jane'],
    ], ['phone']);

    expect($clean)->toBe([
        'old_values' => ['phone' => '******6789', 'name' => 'Jane'],
        'new_values' => ['phone' => '******9999', 'name' => 'Jane'],
    ]);
});

it('redacts inside JSON-encoded string values', function () {
    $clean = $this->redactor->redact([
        'payload' => json_encode(['phone' => '0123456789', 'name' => 'Jane']),
    ], ['phone']);

    expect(json_decode($clean['payload'], true))->toBe([
        'phone' => '******6789',
        'name' => 'Jane',
    ]);
});

it('masks every scalar leaf when a listed field is itself an array', function () {
    $clean = $this->redactor->redact([
        'phones' => ['0123456789', '0199999999'],
    ], ['phones']);

    expect($clean)->toBe([
        'phones' => ['******6789', '******9999'],
    ]);
});

it('masks a listed field carrying a JSON string', function () {
    $clean = $this->redactor->redact([
        'national_id' => json_encode(['value' => '900101011234']),
    ], ['national_id']);

    expect(json_decode($clean['national_id'], true))->toBe([
        'value' => '********1234',
    ]);
});

it('leaves null values untouched when listed', function () {
    $clean = $this->redactor->redact(['phone' => null], ['phone']);

    expect($clean)->toBe(['phone' => null]);
});

it('returns an untouched copy when no fields match', function () {
    $data = ['name' => 'Jane', 'city' => 'KL'];

    expect($this->redactor->redact($data, ['phone']))->toBe($data);
});
