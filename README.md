# squareexp/idp-laravel

Laravel SDK for integrating with Base IDP.

## Install

```bash
composer require squareexp/idp-laravel
php artisan vendor:publish --tag=square-idp-config
```

## Minimal Environment

```env
BASE_IDP_CLIENT_ID=<your-client-id>
BASE_IDP_CLIENT_SECRET=<your-client-secret-if-confidential>
```

That is enough for most Laravel apps. Base resolves redirect URIs, scopes, audience, and allowed auth methods from the client registration.
Use `BASE_IDP_CLIENT_SECRET` for new projects; `BASE_IDP_SECRET` is kept as a legacy alias by older package versions.

## Login Redirect Route

```php
use SquareExp\IdpLaravel\Http\Controllers\SquareLoginController;

Route::get('/auth/square/login', SquareLoginController::class);
```

## Callback Route

```php
use SquareExp\IdpLaravel\Http\Controllers\SquareCallbackController;

Route::get('/auth/square/callback', SquareCallbackController::class);
```

In production, create your own app session after callback handling.

## Protect Routes with Scope

```php
Route::middleware('square.idp:crm:read')->get('/api/customers', function (\Illuminate\Http\Request $request) {
    $principal = $request->attributes->get('square_principal');
    return ['user' => $principal->id];
});
```

## Direct Manager Usage

```php
use SquareExp\IdpLaravel\SquareIdpManager;

$tokens = app(SquareIdpManager::class)->exchangeCode($code);
$principal = app(SquareIdpManager::class)->verifyAccessToken($tokens['access_token'], 'crm:read');
```
