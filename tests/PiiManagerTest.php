<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Encryption\OpenSslEncrypter;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;
use CleaniqueCoders\PiiProtection\PiiManager;

beforeEach(function () {
    $this->manager = new PiiManager(
        new OpenSslEncrypter(key: 'super-secret-key'),
        new TailStrategy(visible: 4),
    );
});

it('delegates encrypt and decrypt to the encrypter', function () {
    $cipher = $this->manager->encrypt('012345678');

    expect($cipher)->not->toBe('012345678')
        ->and($this->manager->decrypt($cipher))->toBe('012345678');
});

it('delegates masking to the strategy', function () {
    expect($this->manager->mask('0123456789'))->toBe('******6789');
});

it('redacts payloads using the configured strategy', function () {
    $clean = $this->manager->redact([
        'phone' => '0123456789',
        'name' => 'Jane',
    ], ['phone']);

    expect($clean)->toBe([
        'phone' => '******6789',
        'name' => 'Jane',
    ]);
});
