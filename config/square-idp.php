<?php

return [
    'client_id' => env('BASE_IDP_CLIENT_ID'),
    'secret' => env('BASE_IDP_CLIENT_SECRET', env('BASE_IDP_SECRET')),
    'issuer' => null,
    'required_scope' => null,
    'public_key_base64' => env('BASE_IDP_PUBLIC_KEY_BASE64'),
    'cache_ttl_seconds' => env('BASE_IDP_KEY_CACHE_TTL', 300),
    'clock_skew_seconds' => env('BASE_IDP_CLOCK_SKEW_SECONDS', 30),
];
