<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Replace the whole value with a fixed placeholder, revealing nothing about
 * the original — not even how long it was.
 *
 * This is the strategy to use for credentials. FullStrategy is length
 * preserving: "hunter2" becomes "*******". That suits PII, where a masked
 * address still reads as an address. For a secret the length is itself a
 * disclosure — it separates a 16-character API key from a 64-character
 * session token, and narrows an offline guess.
 */
final class RedactedStrategy implements MaskStrategy
{
    public function __construct(private string $placeholder = '[redacted]') {}

    public function mask(string $value): string
    {
        return $this->placeholder;
    }
}
