<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Keep the first initial of each word and mask the remaining characters.
 *
 * "John Doe" => "J*** D**"
 */
final class NameStrategy implements MaskStrategy
{
    public function __construct(private string $maskChar = '*') {}

    public function mask(string $value): string
    {
        $words = explode(' ', $value);

        $masked = array_map(function (string $word): string {
            $length = mb_strlen($word);

            if ($length === 0) {
                return $word;
            }

            return mb_substr($word, 0, 1).str_repeat($this->maskChar, $length - 1);
        }, $words);

        return implode(' ', $masked);
    }
}
