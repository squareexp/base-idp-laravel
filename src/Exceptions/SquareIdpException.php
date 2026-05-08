<?php

namespace SquareExp\IdpLaravel\Exceptions;

use RuntimeException;

final class SquareIdpException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly ?int $status = null,
        public readonly mixed $details = null,
    ) {
        parent::__construct($message);
    }
}
