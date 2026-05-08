<?php

namespace SquareExp\IdpLaravel\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SquareExp\IdpLaravel\SquareIdpManager;

final class SquareCallbackController
{
    public function __invoke(Request $request, SquareIdpManager $idp): JsonResponse
    {
        $code = (string) $request->query('code', '');
        if ($code === '') {
            return response()->json(['error' => 'missing_code'], 400);
        }

        $tokens = $idp->exchangeCode($code, $request->session()->pull('square_idp_code_verifier'));
        $principal = $idp->verifyAccessToken($tokens['access_token']);

        return response()->json([
            'ok' => true,
            'state' => $request->query('state'),
            'principal' => [
                'id' => $principal->id,
                'email' => $principal->email,
                'role' => $principal->role,
                'scopes' => $principal->scopes,
            ],
            'tokens' => $tokens,
        ]);
    }
}
