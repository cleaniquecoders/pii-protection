<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Attributes\Pii;
use CleaniqueCoders\PiiProtection\Masking\EmailStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\TailStrategy;
use CleaniqueCoders\PiiProtection\ObjectRedactor;

class RedactorUser
{
    #[Pii]
    public string $name = 'John Doe';

    #[Pii(strategy: EmailStrategy::class)]
    public string $email = 'john@acme.com';

    #[Pii(strategy: TailStrategy::class)]
    public string $phone = '0123456789';

    public int $age = 30;
}

class PartialUser
{
    #[Pii]
    public string $name;

    public string $city = 'KL';
}

it('masks tagged public properties and copies the rest', function () {
    $clean = (new ObjectRedactor(new FullStrategy))->redact(new RedactorUser);

    expect($clean)->toBe([
        'name' => '********',          // default strategy (FullStrategy)
        'email' => '****@acme.com',    // EmailStrategy
        'phone' => '******6789',       // TailStrategy (default visible: 4)
        'age' => 30,                   // untagged, untouched
    ]);
});

it('renders uninitialized public properties as null', function () {
    $clean = (new ObjectRedactor(new FullStrategy))->redact(new PartialUser);

    expect($clean)->toBe(['name' => null, 'city' => 'KL']);
});

it('falls back to the default strategy for a bare #[Pii]', function () {
    $object = new class
    {
        #[Pii]
        public string $secret = 'abcd';
    };

    expect((new ObjectRedactor(new TailStrategy(visible: 2)))->redact($object))
        ->toBe(['secret' => '**cd']);
});
