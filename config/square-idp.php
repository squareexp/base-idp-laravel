<?php

return [
    'issuer' => env('BASE_IDP_ISSUER', 'https://authlayer.squareexp.com'),
    'client_id' => env('BASE_IDP_CLIENT_ID'),
    'client_secret' => env('BASE_IDP_CLIENT_SECRET'),
    'redirect_uri' => env('BASE_IDP_REDIRECT_URI'),
    'scopes' => env('BASE_IDP_SCOPES', 'openid profile'),
    'required_scope' => env('BASE_IDP_REQUIRED_SCOPE'),
    'audience' => env('BASE_IDP_AUDIENCE', 'square-experience'),
    'public_key_base64' => env('BASE_IDP_PUBLIC_KEY_BASE64'),
    'cache_ttl_seconds' => env('BASE_IDP_KEY_CACHE_TTL', 300),
    'clock_skew_seconds' => env('BASE_IDP_CLOCK_SKEW_SECONDS', 30),
];
