<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Masking\CreditCardStrategy;
use CleaniqueCoders\PiiProtection\Masking\IpStrategy;
use CleaniqueCoders\PiiProtection\Masking\NameStrategy;
use CleaniqueCoders\PiiProtection\Masking\NricStrategy;

// CreditCardStrategy
it('keeps the last 4 digits of a card and preserves grouping', function () {
    expect((new CreditCardStrategy)->mask('4111 1111 1111 1111'))
        ->toBe('**** **** **** 1111');
});

it('masks a dash-grouped card', function () {
    expect((new CreditCardStrategy)->mask('4111-1111-1111-1111'))
        ->toBe('****-****-****-1111');
});

it('masks a card with no separators', function () {
    expect((new CreditCardStrategy)->mask('4111111111111111'))
        ->toBe('************1111');
});

// IpStrategy
it('masks the last octet of an IPv4 address', function () {
    expect((new IpStrategy)->mask('192.168.1.42'))->toBe('192.168.1.**');
});

it('masks the last group of an IPv6 address', function () {
    expect((new IpStrategy)->mask('2001:db8:0:0:0:0:0:1'))
        ->toBe('2001:db8:0:0:0:0:0:*');
});

it('masks the last non-empty IPv6 group with trailing ::', function () {
    expect((new IpStrategy)->mask('2001:db8::1'))->toBe('2001:db8::*');
});

// NameStrategy
it('keeps the initial of each word', function () {
    expect((new NameStrategy)->mask('John Doe'))->toBe('J*** D**');
});

it('handles a single-word name', function () {
    expect((new NameStrategy)->mask('Jane'))->toBe('J***');
});

// NricStrategy
it('masks all digits of an NRIC by default, keeping dashes', function () {
    expect((new NricStrategy)->mask('900101-01-1234'))->toBe('******-**-****');
});

it('keeps the birth-date portion when requested', function () {
    expect((new NricStrategy(keepBirthDate: true))->mask('900101-01-1234'))
        ->toBe('900101-**-****');
});

it('masks an NRIC without dashes', function () {
    expect((new NricStrategy)->mask('900101011234'))->toBe('************');
});
