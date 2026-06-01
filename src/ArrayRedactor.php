<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection;

use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\Contracts\Redactor;

final class ArrayRedactor implements Redactor
{
    public function __construct(private MaskStrategy $strategy) {}

    /**
     * Walk a key/value payload and mask the listed fields, recursing into
     * nested arrays and JSON-decoded structures. Non-listed fields are
     * returned untouched.
     *
     * $fields accepts, in any combination:
     *   - a plain field name ("phone") — matched at any depth using the
     *     default strategy;
     *   - a field name mapped to a strategy (["email" => new EmailStrategy]);
     *   - a dot-path with optional "*" wildcards ("user.phone",
     *     "users.*.phone"), as a value or as a strategy-mapped key.
     *
     * @param  array<array-key,mixed>  $data
     * @param  array<int|string,string|MaskStrategy>  $fields
     * @return array<array-key,mixed>
     */
    public function redact(array $data, array $fields): array
    {
        [$nameStrategies, $pathStrategies] = $this->normalise($fields);

        $result = $this->redactByName($data, $nameStrategies);

        foreach ($pathStrategies as $path => $strategy) {
            $result = $this->redactByPath($result, explode('.', $path), $strategy);
        }

        return $result;
    }

    /**
     * Split the field list into name-based and path-based strategy maps.
     *
     * @param  array<int|string,string|MaskStrategy>  $fields
     * @return array{0: array<string,MaskStrategy>, 1: array<string,MaskStrategy>}
     */
    private function normalise(array $fields): array
    {
        $names = [];
        $paths = [];

        foreach ($fields as $key => $value) {
            if ($value instanceof MaskStrategy) {
                $field = (string) $key;
                $strategy = $value;
            } else {
                $field = $value;
                $strategy = $this->strategy;
            }

            if (str_contains($field, '.')) {
                $paths[$field] = $strategy;
            } else {
                $names[$field] = $strategy;
            }
        }

        return [$names, $paths];
    }

    /**
     * Recursively mask any key whose name is listed, at any depth.
     *
     * @param  array<array-key,mixed>  $data
     * @param  array<string,MaskStrategy>  $nameStrategies
     * @return array<array-key,mixed>
     */
    private function redactByName(array $data, array $nameStrategies): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            $name = (string) $key;

            if (isset($nameStrategies[$name])) {
                $result[$key] = $this->maskValue($value, $nameStrategies[$name]);

                continue;
            }

            if (is_array($value)) {
                $result[$key] = $this->redactByName($value, $nameStrategies);

                continue;
            }

            if (is_string($value) && is_array($decoded = $this->jsonToArray($value))) {
                $result[$key] = (string) json_encode($this->redactByName($decoded, $nameStrategies));

                continue;
            }

            $result[$key] = $value;
        }

        return $result;
    }

    /**
     * Mask the leaf(s) reached by following a dot-path, where "*" matches any
     * key at that level.
     *
     * @param  array<array-key,mixed>  $data
     * @param  array<int,string>  $segments
     * @return array<array-key,mixed>
     */
    private function redactByPath(array $data, array $segments, MaskStrategy $strategy): array
    {
        $segment = array_shift($segments);
        $isLast = $segments === [];

        foreach ($data as $key => $value) {
            if ($segment !== '*' && (string) $key !== $segment) {
                continue;
            }

            if ($isLast) {
                $data[$key] = $this->maskValue($value, $strategy);
            } elseif (is_array($value)) {
                $data[$key] = $this->redactByPath($value, $segments, $strategy);
            }
        }

        return $data;
    }

    /**
     * Mask a sensitive value: recurse arrays and JSON, mask scalar leaves.
     */
    private function maskValue(mixed $value, MaskStrategy $strategy): mixed
    {
        if ($value === null) {
            return null;
        }

        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => $this->maskValue($item, $strategy), $value);
        }

        if (is_string($value) && is_array($decoded = $this->jsonToArray($value))) {
            return (string) json_encode($this->maskValue($decoded, $strategy));
        }

        if (is_bool($value)) {
            return $strategy->mask($value ? '1' : '0');
        }

        if (is_scalar($value)) {
            return $strategy->mask((string) $value);
        }

        // Non-stringable values (objects, resources) are left untouched.
        return $value;
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
