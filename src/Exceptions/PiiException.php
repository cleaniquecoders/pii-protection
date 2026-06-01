<?php

declare(strict_types=1);

namespace CleaniqueCoders\PiiProtection\Exceptions;

use RuntimeException;

/**
 * Base exception for the pii-protection package.
 *
 * Extends RuntimeException so existing catch blocks keep working.
 */
class PiiException extends RuntimeException {}
