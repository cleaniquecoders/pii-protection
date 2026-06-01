<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Detection\PiiScrubber;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\RegexStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;

// RegexStrategy
it('masks every substring matching the pattern', function () {
    $strategy = new RegexStrategy('/\d+/', new FullStrategy);

    expect($strategy->mask('call 0123 or 4567'))->toBe('call **** or ****');
});

it('delegates each match to the inner strategy', function () {
    $strategy = new RegexStrategy('/\d{10}/', new TailStrategy(visible: 4));

    expect($strategy->mask('phone 0123456789 end'))->toBe('phone ******6789 end');
});

// PiiScrubber
it('scrubs an email out of free text', function () {
    expect((new PiiScrubber)->scrub('contact john@acme.com now'))
        ->toBe('contact ************* now');
});

it('scrubs a Malaysian NRIC', function () {
    expect((new PiiScrubber)->scrub('id 900101-01-1234 ok'))
        ->toBe('id ************** ok');
});

it('scrubs an IPv4 address', function () {
    expect((new PiiScrubber)->scrub('from 192.168.1.42 today'))
        ->toBe('from ************ today');
});

it('scrubs a 16-digit credit card', function () {
    expect((new PiiScrubber)->scrub('card 4111 1111 1111 1111 end'))
        ->toBe('card ******************* end');
});

it('only scrubs the enabled detector types', function () {
    $scrubber = new PiiScrubber(types: ['email']);

    expect($scrubber->scrub('john@acme.com from 192.168.1.42'))
        ->toBe('************* from 192.168.1.42');
});

it('detects PII without modifying the text', function () {
    $found = (new PiiScrubber)->detect('email john@acme.com ip 192.168.1.42');

    $types = array_column($found, 'type');

    expect($types)->toContain('email')
        ->and($types)->toContain('ipv4')
        ->and($found[0]['value'])->toBe('john@acme.com');
});
