<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Detection;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\Masking\RedactedStrategy;

/**
 * Masks a known set of exact values wherever they appear in free text.
 *
 * The counterpart to pattern detection: when the caller already holds the
 * secrets — a deployment's resolved tokens, the credentials it injected, an
 * API key read from config — an exact match is certain, where a pattern is a
 * guess. Use both. Patterns catch secrets the caller never issued; literals
 * catch the ones with no distinctive shape.
 *
 *     $scrubber->scrub($logLine, [$token, $dbPassword]);
 *
 * Three rules stop this from doing more harm than good, and none of them are
 * obvious until the output is wrong:
 *
 *  - **Longest first.** Masking a short value that happens to sit inside a
 *    longer one corrupts the longer one and leaves part of it exposed.
 *  - **Minimum length.** Blanking every occurrence of a 4-character value
 *    shreds unrelated text.
 *  - **Skip pure digits.** A port, a replica count and a timeout are not
 *    secrets, and masking them everywhere destroys the log's usefulness.
 */
final class LiteralScrubber
{
    /**
     * Shorter values collide with ordinary text too often to mask safely.
     */
    public const MIN_LENGTH = 6;

    private MaskStrategy $strategy;

    public function __construct(
        ?MaskStrategy $strategy = null,
        private int $minLength = self::MIN_LENGTH,
        private bool $skipNumeric = true,
    ) {
        $this->strategy = $strategy ?? new RedactedStrategy;
    }

    /**
     * @param  array<array-key,string|null>  $values
     */
    public function scrub(string $text, array $values): string
    {
        $values = $this->prepare($values);

        if ($values === []) {
            return $text;
        }

        $replacements = array_map(
            fn (string $value): string => $this->strategy->mask($value),
            $values,
        );

        // str_replace walks the arrays in order, so the longest-first sort
        // from prepare() is what makes nested values safe.
        return str_replace($values, $replacements, $text);
    }

    /**
     * Report which of the supplied values appear, without modifying the text.
     *
     * @param  array<array-key,string|null>  $values
     * @return array<int,array{value:string,offset:int}>
     */
    public function detect(string $text, array $values): array
    {
        $found = [];

        foreach ($this->prepare($values) as $value) {
            $offset = 0;

            while (($position = mb_strpos($text, $value, $offset)) !== false) {
                $found[] = ['value' => $value, 'offset' => $position];
                $offset = $position + mb_strlen($value);
            }
        }

        return $found;
    }

    /**
     * The values that would actually be masked, after the safety rules.
     *
     * Exposed so a caller can see why something it passed was skipped rather
     * than concluding the scrubber is broken.
     *
     * @param  array<array-key,string|null>  $values
     * @return array<int,string>
     */
    public function prepare(array $values): array
    {
        $clean = [];

        foreach ($values as $value) {
            if ($value === null) {
                continue;
            }

            $value = trim($value);

            if (mb_strlen($value) < $this->minLength) {
                continue;
            }

            if ($this->skipNumeric && ctype_digit($value)) {
                continue;
            }

            $clean[$value] = true;
        }

        $clean = array_keys($clean);

        usort($clean, static fn (string $a, string $b): int => mb_strlen($b) <=> mb_strlen($a));

        return $clean;
    }
}
