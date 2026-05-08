<?php

namespace SquareExp\IdpLaravel\Facades;

use Illuminate\Support\Facades\Facade;

final class SquareIdp extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'square-idp';
    }
}
