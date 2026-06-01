<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Mask every substring matching a regular expression, delegating each match to
 * an inner strategy. Useful for scrubbing PII out of free text (log lines,
 * messages) rather than named fields.
 */
final class RegexStrategy implements MaskStrategy
{
    public function __construct(
        private string $pattern,
        private MaskStrategy $inner = new FullStrategy,
    ) {}

    public function mask(string $value): string
    {
        $result = preg_replace_callback(
            $this->pattern,
            fn (array $matches): string => $this->inner->mask($matches[0]),
            $value,
        );

        return $result ?? $value;
    }
}
