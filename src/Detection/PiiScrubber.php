<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Detection;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\Masking\FullStrategy;
use CleaniqueCoders\PiiProtection\Masking\RegexStrategy;

/**
 * Scrubs PII out of free text using built-in detectors. Unlike field-based
 * redaction, this scans the text itself — e.g. log lines or messages.
 *
 * Detectors run in a fixed order so that broader patterns (credit cards) are
 * masked before narrower ones (phone numbers) can partially match them.
 */
final class PiiScrubber
{
    /**
     * @var array<string,string> detector type => regex (ordered)
     */
    private const PATTERNS = [
        'email' => '/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/',
        'credit_card' => '/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/',
        'nric' => '/\b\d{6}-\d{2}-\d{4}\b/',
        'ipv4' => '/\b(?:\d{1,3}\.){3}\d{1,3}\b/',
        'phone' => '/\b(?:\+?60|0)\d{1,2}-?\d{3,4}-?\d{4}\b/',
    ];

    private MaskStrategy $strategy;

    /**
     * @var array<int,string> enabled detector types
     */
    private array $types;

    /**
     * @param  array<int,string>|null  $types  detector types to enable (default: all)
     */
    public function __construct(?MaskStrategy $strategy = null, ?array $types = null)
    {
        $this->strategy = $strategy ?? new FullStrategy;
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
     * Report detected PII without modifying the text.
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
}
