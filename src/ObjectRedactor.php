<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection;

use CleaniqueCoders\PiiProtection\Attributes\Pii;
use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use ReflectionObject;

/**
 * Redacts an object into an array, masking every public property tagged with
 * the {@see Pii} attribute. A tagged property may name its own strategy;
 * otherwise the redactor's default strategy is used. Untagged properties are
 * copied through untouched.
 */
final class ObjectRedactor
{
    public function __construct(private MaskStrategy $strategy) {}

    /**
     * @return array<string,mixed>
     */
    public function redact(object $object): array
    {
        $result = [];

        foreach ((new ReflectionObject($object))->getProperties() as $property) {
            if (! $property->isPublic()) {
                continue;
            }

            $name = $property->getName();

            if (! $property->isInitialized($object)) {
                $result[$name] = null;

                continue;
            }

            $value = $property->getValue($object);

            $attributes = $property->getAttributes(Pii::class);

            if ($attributes === []) {
                $result[$name] = $value;

                continue;
            }

            $result[$name] = $this->maskValue($value, $this->resolveStrategy($attributes[0]->newInstance()));
        }

        return $result;
    }

    private function resolveStrategy(Pii $pii): MaskStrategy
    {
        if ($pii->strategy === null) {
            return $this->strategy;
        }

        return new $pii->strategy;
    }

    private function maskValue(mixed $value, MaskStrategy $strategy): mixed
    {
        if ($value === null) {
            return null;
        }

        if (is_array($value)) {
            return array_map(fn (mixed $item): mixed => $this->maskValue($item, $strategy), $value);
        }

        if (is_bool($value)) {
            return $strategy->mask($value ? '1' : '0');
        }

        if (is_scalar($value)) {
            return $strategy->mask((string) $value);
        }

        return $value;
    }
}
