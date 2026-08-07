<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Detection;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\Masking\RedactedStrategy;
use CleaniqueCoders\PiiProtection\Masking\RegexStrategy;

/**
 * Scrubs machine credentials out of free text — log lines, exception
 * messages, HTTP payloads, queue job arguments.
 *
 * The sibling of PiiScrubber, and deliberately separate from it. PiiScrubber
 * finds *personal* data (email, phone, NRIC, IP); this finds *secrets* (keys,
 * tokens, passwords). The two sets do not overlap, and running the wrong one
 * does real damage: scrubbing every IP and email address out of an
 * infrastructure log removes exactly the detail needed to debug it.
 *
 * Several patterns use `\K` to reset the reported match, so the surrounding
 * context survives and the output stays diagnosable:
 *
 *     DB_PASSWORD=hunter2         → DB_PASSWORD=[redacted]
 *     postgres://app:s3cr3t@db    → postgres://app:[redacted]@db
 *
 * Knowing *which* credential leaked is most of the value of the log line.
 *
 * Detection is best-effort. It cannot recognise a secret with no distinctive
 * shape and no telling name — pair it with LiteralScrubber when the exact
 * values are known.
 */
final class SecretScrubber
{
    /**
     * Detector type => regex, in application order.
     *
     * Ordered most-structural first, so `detect()` reports the most specific
     * type for a value that several patterns could claim.
     *
     * @var array<string,string>
     */
    private const PATTERNS = [
        // Whole PEM block including its armour. Must run first: it spans
        // newlines and would otherwise be shredded by the narrower patterns.
        'private_key' => '/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/s',

        // scheme://user:password@host — keeps the scheme, user and host.
        'url_credentials' => '#[a-z][a-z0-9+.\-]*://[^\s:@/]*:\K[^\s@/]+(?=@)#i',

        'jwt' => '/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/',

        // AWS access key IDs — the documented prefixes for each identity type.
        'aws_access_key_id' => '/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b/',

        // Authorization headers — keeps the scheme word.
        'authorization' => '/\b(?:bearer|basic)\s+\K[A-Za-z0-9._\-\/+=]{12,}/i',

        // SENSITIVE_KEY=value / "sensitive_key": "value" — keeps the key.
        // `_keys?` is underscored so an assignment named sortkey= survives.
        // The optional quote picks up JSON keys; the lookahead stands down
        // for `Authorization: Bearer x`, whose name contains "auth" but
        // whose value the authorization detector splits more usefully.
        'assignment' => '/[A-Za-z0-9_.\-]*(?:password|passwd|pass|secret|token|apikey|api_key|private_key|access_key|credentials?|auth|_keys?)[A-Za-z0-9_.\-]*["\']?\s*[=:]\s*\K(?!(?:bearer|basic)\b)(?:"[^"]*"|\'[^\']*\'|[^\s,;&]+)/i',
    ];

    private MaskStrategy $strategy;

    /** @var array<int,string> enabled detector types */
    private array $types;

    /**
     * @param  array<int,string>|null  $types  detector types to enable (default: all)
     */
    public function __construct(?MaskStrategy $strategy = null, ?array $types = null)
    {
        $this->strategy = $strategy ?? new RedactedStrategy;
        $this->types = $types ?? array_keys(self::PATTERNS);
    }

    public function scrub(string $text): string
    {
        foreach (self::PATTERNS as $type => $pattern) {
            if (! in_array($type, $this->types, true)) {
                continue;
            }

            $text = (new RegexStrategy($pattern, $this->strategy))->mask($text);
        }

        return $text;
    }

    /**
     * Report detected secrets without modifying the text.
     *
     * @return array<int,array{type:string,value:string,offset:int}>
     */
    public function detect(string $text): array
    {
        $found = [];

        foreach (self::PATTERNS as $type => $pattern) {
            if (! in_array($type, $this->types, true)) {
                continue;
            }

            if (preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE) === false) {
                continue;
            }

            foreach ($matches[0] as $match) {
                $found[] = [
                    'type' => $type,
                    'value' => (string) $match[0],
                    'offset' => (int) $match[1],
                ];
            }
        }

        return $found;
    }

    /**
     * The detector types this scrubber knows about.
     *
     * @return array<int,string>
     */
    public static function types(): array
    {
        return array_keys(self::PATTERNS);
    }
}
