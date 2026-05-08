<?php

namespace SquareExp\IdpLaravel\Contracts;

final class SquarePrincipal
{
    public function __construct(
        public readonly string $id,
        public readonly string $subject,
        public readonly ?string $email,
        public readonly ?string $name,
        public readonly string $role,
        public readonly array $scopes,
        public readonly array $accountContext,
        public readonly array $claims,
    ) {
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
