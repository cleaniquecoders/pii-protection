<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Attributes;

use Attribute;
use CleaniqueCoders\PiiProtection\Contracts\MaskStrategy;
use CleaniqueCoders\PiiProtection\ObjectRedactor;

/**
 * Marks an object property as PII so {@see ObjectRedactor}
 * masks it. Optionally name a MaskStrategy class to override the redactor's
 * default; the class is instantiated with no arguments (its own defaults).
 */
#[Attribute(Attribute::TARGET_PROPERTY)]
final class Pii
{
    /**
     * @param  class-string<MaskStrategy>|null  $strategy
     */
    public function __construct(public ?string $strategy = null) {}
}
