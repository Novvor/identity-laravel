<?php

$identityBaseUrl = env('IDENTITY_ERROR_SURFACE_BASE_URL')
    ?: env('IDENTITY_OIDC_PUBLIC_BASE_URL')
    ?: env('IDENTITY_OIDC_ISSUER')
    ?: '';

$appKey = env('IDENTITY_ERROR_APP_KEY')
    ?: env('IDENTITY_APP_KEY')
    ?: env('IDENTITY_OIDC_CLIENT_ID')
    ?: env('APP_NAME', 'external-app');

return [
    'enabled' => (bool) env('IDENTITY_ENABLED', true),
    'validate_on_boot' => (bool) env('IDENTITY_VALIDATE_ON_BOOT', true),

    /*
    |--------------------------------------------------------------------------
    | Identity 2.0 OIDC relying-party contract
    |--------------------------------------------------------------------------
    |
    | Production must provide every endpoint explicitly. No endpoint is derived
    | from APP_URL, the request Host header, localhost, or a .test fallback.
    |
    */
    'oidc' => [
        'issuer' => env('IDENTITY_OIDC_ISSUER'),
        'client_id' => env('IDENTITY_OIDC_CLIENT_ID'),
        'client_secret' => env('IDENTITY_OIDC_CLIENT_SECRET'),
        'redirect_uri' => env('IDENTITY_OIDC_REDIRECT_URI'),
        'authorization_endpoint' => env('IDENTITY_OIDC_AUTHORIZATION_ENDPOINT'),
        'token_endpoint' => env('IDENTITY_OIDC_TOKEN_ENDPOINT'),
        'jwks_uri' => env('IDENTITY_OIDC_JWKS_URI'),
        'userinfo_endpoint' => env('IDENTITY_OIDC_USERINFO_ENDPOINT'),
        'introspection_endpoint' => env('IDENTITY_OIDC_INTROSPECTION_ENDPOINT'),
        'revocation_endpoint' => env('IDENTITY_OIDC_REVOCATION_ENDPOINT'),
        'client_authentication_method' => env('IDENTITY_OIDC_CLIENT_AUTH_METHOD', 'none'),
        'private_key' => env('IDENTITY_OIDC_PRIVATE_KEY'),
        'private_key_id' => env('IDENTITY_OIDC_PRIVATE_KEY_ID'),
        'profile' => env('IDENTITY_OIDC_PROFILE', 'standard'),
        'scopes' => env('IDENTITY_OIDC_SCOPES', 'openid profile email'),
        'http_timeout_seconds' => (int) env('IDENTITY_OIDC_HTTP_TIMEOUT', 5),
        'jwks_cache_ttl_seconds' => (int) env('IDENTITY_OIDC_JWKS_CACHE_TTL', 300),
        'transaction_ttl_seconds' => (int) env('IDENTITY_OIDC_TRANSACTION_TTL', 600),
        'max_pending_transactions' => (int) env('IDENTITY_OIDC_MAX_PENDING_TRANSACTIONS', 5),
        // Authorization intent material is server-side only. Production must bind this
        // explicitly to a shared, lock-capable cache store (typically Redis).
        'intent_cache_store' => env('IDENTITY_OIDC_INTENT_CACHE_STORE'),
        'intent_lock_seconds' => (int) env('IDENTITY_OIDC_INTENT_LOCK_SECONDS', 5),
    ],

    'token_validation_policy' => Novvor\Identity\Jwt\IdentityTokenValidationPolicy::class,
    'session_mapper' => Novvor\Identity\Session\IdentitySessionMapper::class,

    'error_surface' => [
        'identity_base_url' => rtrim((string) $identityBaseUrl, '/'),
        'app_key' => $appKey,
        'return_url' => env('IDENTITY_ERROR_RETURN_URL'),
        'default_code' => 'identity_login_failed',
        'default_message' => 'No se pudo completar el inicio de sesión.',
        'path' => '/auth/identity/error',
    ],
];
