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
