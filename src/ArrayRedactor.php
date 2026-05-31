<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\Contracts\Redactor;

final class ArrayRedactor implements Redactor
{
    public function __construct(private MaskStrategy $strategy) {}

    /**
     * Walk a key/value payload and mask every listed field, recursing into
     * nested arrays and JSON-decoded structures. Non-listed fields are
     * returned untouched.
     *
     * @param  array<string,mixed>  $data
     * @param  array<int,string>  $fields
     * @return array<string,mixed>
     */
    public function redact(array $data, array $fields): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            if (in_array((string) $key, $fields, true)) {
                $result[$key] = $this->maskValue($value);

                continue;
            }

            if (is_array($value)) {
                $result[$key] = $this->redact($value, $fields);

                continue;
            }

            if (is_string($value) && is_array($decoded = $this->jsonToArray($value))) {
                $result[$key] = (string) json_encode($this->redact($decoded, $fields));

                continue;
            }

            $result[$key] = $value;
        }

        return $result;
    }

    /**
     * Mask a sensitive value: recurse arrays and JSON, mask scalar leaves.
     */
    private function maskValue(mixed $value): mixed
    {
        if ($value === null) {
            return null;
        }

        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => $this->maskValue($item), $value);
        }

        if (is_string($value) && is_array($decoded = $this->jsonToArray($value))) {
            return (string) json_encode($this->maskValue($decoded));
        }

        return $this->strategy->mask((string) $value);
    }

    /**
     * Decode a JSON string to an array, or return null if it is not a JSON
     * array/object.
     *
     * @return array<mixed>|null
     */
    private function jsonToArray(string $value): ?array
    {
        $decoded = json_decode($value, true);

        return json_last_error() === JSON_ERROR_NONE && is_array($decoded)
            ? $decoded
            : null;
    }
}
