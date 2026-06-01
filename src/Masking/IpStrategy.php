<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Masking;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;

/**
 * Mask the last segment of an IP address: the final octet for IPv4 and the
 * final group for IPv6.
 *
 * "192.168.1.42"  => "192.168.1.**"
 * "2001:db8::1"   => "2001:db8::*"
 */
final class IpStrategy implements MaskStrategy
{
    public function __construct(private string $maskChar = '*') {}

    public function mask(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        $separator = str_contains($value, ':') ? ':' : '.';
        $segments = explode($separator, $value);

        // Mask the last non-empty segment (handles trailing "::" in IPv6).
        for ($i = count($segments) - 1; $i >= 0; $i--) {
            if ($segments[$i] !== '') {
                $segments[$i] = str_repeat($this->maskChar, mb_strlen($segments[$i]));
                break;
            }
        }

        return implode($separator, $segments);
    }
}
