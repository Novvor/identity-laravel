# Upgrading from 1.x

1. Replace `novvor/identity-sdk` with `novvor/identity-laravel`.
2. Configure every issuer and endpoint explicitly.
3. Replace custom redirect/callback code with `IdentityAuthorizationManager`.
4. Register an exact callback URI in Identity.
5. For high assurance, register the backend public key and configure
   `private_key_jwt`.
6. Remove code that derives Identity hosts from `APP_URL` or request headers.
7. Map the validated result to application tenant and role policies.
8. Run positive and negative callback, replay, issuer and tenant tests.

There is no transparent compatibility mode because 2.0 intentionally removes
unsafe fallback behavior.

# Upgrading from 2.0 to 2.5

1. Upgrade the core and adapter together after their stable 2.5 releases are
   available:

   ```bash
   composer require novvor/identity-laravel:^2.5 novvor/identity-sdk-php:^2.5
   ```

2. Configure `IDENTITY_OIDC_INTENT_CACHE_STORE` to a shared Laravel cache store
   with atomic locks (normally Redis) and set `IDENTITY_OIDC_INTENT_LOCK_SECONDS`
   between 1 and 30.
3. Do not store a transaction, PKCE verifier, `state`, `nonce` or DPoP private
   material in the browser session. The 2.5 manager stores only opaque handles
   there and fails closed when its server-side intent cannot be recovered.
4. Test two concurrent callbacks for the same authorization response: exactly
   one must reach token exchange.
5. Deploy the cache configuration before enabling the new adapter version on
   every web and worker process.
