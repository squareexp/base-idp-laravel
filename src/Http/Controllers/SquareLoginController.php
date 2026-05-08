<?php

namespace SquareExp\IdpLaravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use SquareExp\IdpLaravel\SquareIdpManager;

final class SquareLoginController
{
    public function __invoke(Request $request, SquareIdpManager $idp): RedirectResponse
    {
        $returnTo = (string) $request->query('return_to', url()->previous() ?: '/');

        return redirect()->away($idp->authorizeUrl([
            'state' => $returnTo,
        ]));
    }
}
