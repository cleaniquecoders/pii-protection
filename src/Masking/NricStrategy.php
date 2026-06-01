<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Mask a Malaysian NRIC / MyKad number (YYMMDD-PB-###G), preserving any
 * dashes. By default every digit is masked; set $keepBirthDate to keep the
 * leading 6-digit birth-date portion visible.
 *
 * "900101-01-1234" => "******-**-****"           (default)
 * "900101-01-1234" => "900101-**-****"           (keepBirthDate: true)
 */
final class NricStrategy implements MaskStrategy
{
    public function __construct(
        private bool $keepBirthDate = false,
        private string $maskChar = '*',
    ) {}

    public function mask(string $value): string
    {
        $keep = $this->keepBirthDate ? 6 : 0;

        $seen = 0;
        $out = '';
        foreach (mb_str_split($value) as $char) {
            if (ctype_digit($char)) {
                $seen++;
                $out .= $seen <= $keep ? $char : $this->maskChar;
            } else {
                $out .= $char;
            }
        }

        return $out;
    }
}
