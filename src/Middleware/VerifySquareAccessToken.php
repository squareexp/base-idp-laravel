<?php

namespace SquareExp\IdpLaravel\Middleware;

use Closure;
use Illuminate\Http\Request;
use SquareExp\IdpLaravel\Exceptions\SquareIdpException;
use SquareExp\IdpLaravel\SquareIdpManager;
use Symfony\Component\HttpFoundation\Response;

final class VerifySquareAccessToken
{
    public function __construct(private readonly SquareIdpManager $idp)
    {
    }

    public function handle(Request $request, Closure $next, ?string $scope = null): Response
    {
        $token = $request->bearerToken();
        if (!$token) {
            return response()->json(['error' => 'missing_bearer_token'], 401);
        }

        try {
            $principal = $this->idp->verifyAccessToken($token, $scope);
        } catch (SquareIdpException $error) {
            return response()->json([
                'error' => $error->errorCode,
                'message' => $error->getMessage(),
            ], in_array($error->errorCode, ['insufficient_scope'], true) ? 403 : 401);
        }

        $request->attributes->set('square_principal', $principal);
        $request->attributes->set('square_claims', $principal->claims);

        return $next($request);
    }
}
