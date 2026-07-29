# Compatibility

| Component | Supported |
|---|---|
| PHP | 8.2–8.5 |
| Laravel | 12–13 |
| Identity core | 2.x |
| OAuth | Authorization Code, refresh, introspection, revocation |
| OIDC | Discovery, RFC 9207, ID Token, UserInfo |
| High assurance | PKCE S256, PAR, JARM RS256, DPoP ES256, private_key_jwt |

`novvor/identity-laravel` 2.x is a breaking replacement for the legacy package
formerly distributed as `novvor/identity-sdk` 1.x.

Automatic DPoP nonce challenge retries, OpenID certification, SAML and SCIM are
not claimed by this package.
