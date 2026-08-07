<?php

declare(strict_types=1);

use CleaniqueCoders\PiiProtection\Detection\PiiScrubber;
use CleaniqueCoders\PiiProtection\Detection\SecretScrubber;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;

it('scrubs a PEM private key block including its armour', function () {
    $text = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----\ndone";

    expect((new SecretScrubber)->scrub($text))
        ->toBe("key:\n[redacted]\ndone");
});

it('scrubs any PEM private key type', function () {
    foreach (['RSA ', 'EC ', 'OPENSSH ', ''] as $type) {
        $text = "-----BEGIN {$type}PRIVATE KEY-----\nAAAA\n-----END {$type}PRIVATE KEY-----";

        expect((new SecretScrubber)->scrub($text))->toBe('[redacted]');
    }
});

it('scrubs the password out of a connection string but keeps the rest', function () {
    // Knowing it was postgres, user app, host db is most of the value of the
    // log line — only the password has to go.
    expect((new SecretScrubber)->scrub('connecting to postgres://app:s3cr3t@db:5432/app'))
        ->toBe('connecting to postgres://app:[redacted]@db:5432/app');
});

it('scrubs a redis url with no username', function () {
    expect((new SecretScrubber)->scrub('redis://:p4ssw0rd@cache:6379/0'))
        ->toContain('[redacted]')
        ->not->toContain('p4ssw0rd');
});

it('scrubs a JWT', function () {
    $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u';

    expect((new SecretScrubber)->scrub("token {$jwt} end"))
        ->toBe('token [redacted] end');
});

it('scrubs AWS access key ids of every identity prefix', function () {
    foreach (['AKIA', 'ASIA', 'AGPA', 'AIDA', 'AROA', 'ANPA', 'ANVA'] as $prefix) {
        $key = $prefix.'IOSFODNN7EXAMPLE';

        expect((new SecretScrubber)->scrub("key {$key} used"))->toBe('key [redacted] used');
    }
});

it('scrubs an authorization header but keeps the scheme', function () {
    expect((new SecretScrubber)->scrub('Authorization: Bearer abcdefghijklmnop12345'))
        ->toBe('Authorization: Bearer [redacted]');

    expect((new SecretScrubber)->scrub('Authorization: Basic dXNlcjpwYXNzd29yZA=='))
        ->toBe('Authorization: Basic [redacted]');
});

it('scrubs a sensitive assignment but keeps the key name', function () {
    // Which variable leaked is the actionable part.
    expect((new SecretScrubber)->scrub('DB_PASSWORD=hunter2 APP_ENV=production'))
        ->toBe('DB_PASSWORD=[redacted] APP_ENV=production');
});

it('scrubs quoted and json-style assignments', function () {
    expect((new SecretScrubber)->scrub('{"api_token": "ghp_16CharsAtLeast99"}'))
        ->toContain('[redacted]')
        ->not->toContain('ghp_16CharsAtLeast99');

    expect((new SecretScrubber)->scrub("SECRET_KEY='base64:AAAA'"))
        ->not->toContain('base64:AAAA');
});

it('leaves ordinary configuration readable', function () {
    $text = 'APP_ENV=production LOG_LEVEL=debug sortkey=name replicas=3 port=5432';

    // Over-masking is its own failure: a log with every value blanked is
    // no more useful than no log.
    expect((new SecretScrubber)->scrub($text))->toBe($text);
});

it('leaves a bare uuid and a git sha alone', function () {
    $text = 'deployment 3f2504e0-4f89-11d3-9a0c-0305e82c3301 at a1b2c3d4e5f6';

    expect((new SecretScrubber)->scrub($text))->toBe($text);
});

it('does not touch PII, which is PiiScrubber\'s job', function () {
    // The two scrubbers are deliberately disjoint. Scrubbing IPs and emails
    // out of an infrastructure log would remove what you need to debug it.
    $text = 'node 192.168.1.42 owned by ops@example.com';

    expect((new SecretScrubber)->scrub($text))->toBe($text)
        ->and((new PiiScrubber)->scrub($text))->not->toBe($text);
});

it('accepts a different mask strategy', function () {
    expect((new SecretScrubber(new FullStrategy))->scrub('DB_PASSWORD=hunter2'))
        ->toBe('DB_PASSWORD=*******');
});

it('can be narrowed to specific detector types', function () {
    $jwtOnly = new SecretScrubber(types: ['jwt']);
    $text = 'DB_PASSWORD=hunter2 and eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u';

    expect($jwtOnly->scrub($text))
        ->toContain('DB_PASSWORD=hunter2')
        ->toContain('[redacted]');
});

it('reports what it found without modifying the text', function () {
    $text = 'DB_PASSWORD=hunter2 key AKIAIOSFODNN7EXAMPLE';

    $found = (new SecretScrubber)->detect($text);
    $types = array_column($found, 'type');

    expect($types)->toContain('aws_access_key_id')
        ->and($types)->toContain('assignment')
        ->and($found[0])->toHaveKeys(['type', 'value', 'offset']);
});

it('reports nothing for clean text', function () {
    expect((new SecretScrubber)->detect('APP_ENV=production'))->toBe([]);
});

it('exposes its detector types', function () {
    expect(SecretScrubber::types())
        ->toContain('private_key')
        ->toContain('url_credentials')
        ->toContain('jwt')
        ->toContain('aws_access_key_id')
        ->toContain('authorization')
        ->toContain('assignment');
});

it('is idempotent — scrubbing twice changes nothing further', function () {
    $text = 'DB_PASSWORD=hunter2 postgres://app:s3cr3t@db/app';
    $scrubber = new SecretScrubber;

    $once = $scrubber->scrub($text);

    expect($scrubber->scrub($once))->toBe($once);
});

it('handles an empty string', function () {
    expect((new SecretScrubber)->scrub(''))->toBe('');
});

it('scrubs several secrets in one line', function () {
    $result = (new SecretScrubber)->scrub(
        'DB_PASSWORD=hunter2 AWS=AKIAIOSFODNN7EXAMPLE url=postgres://u:p4ss@h/d'
    );

    expect($result)->not->toContain('hunter2')
        ->not->toContain('AKIAIOSFODNN7EXAMPLE')
        ->not->toContain('p4ss@');
});
