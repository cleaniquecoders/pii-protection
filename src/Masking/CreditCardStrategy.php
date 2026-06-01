<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Keep the last N digits of a card number, mask the rest, and preserve any
 * grouping characters (spaces, dashes).
 *
 * "4111 1111 1111 1111" => "**** **** **** 1111"
 */
final class CreditCardStrategy implements MaskStrategy
{
    public function __construct(
        private int $visible = 4,
        private string $maskChar = '*',
    ) {}

    public function mask(string $value): string
    {
        $chars = mb_str_split($value);

        $digitCount = 0;
        foreach ($chars as $char) {
            if (ctype_digit($char)) {
                $digitCount++;
            }
        }

        $maskUpTo = max(0, $digitCount - $this->visible);

        $seen = 0;
        $out = '';
        foreach ($chars as $char) {
            if (ctype_digit($char)) {
                $seen++;
                $out .= $seen <= $maskUpTo ? $this->maskChar : $char;
            } else {
                $out .= $char;
            }
        }

        return $out;
    }
}
