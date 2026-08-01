# Changelog

## Unreleased

- Prepared the adapter for `novvor/identity-sdk-php:^2.5`.
- Moved authorization intents, PKCE verifiers and DPoP private material from
  the browser session to encrypted server-side Laravel cache entries.
- Added atomic one-time consumption for authorization intents and DPoP
  material, including bounded lock configuration and production fail-closed
  cache validation.
- Kept only opaque, bounded intent handles in browser sessions and removed the
  legacy in-session transaction payload on a new authorization attempt.
- Added an explicit authorization-start result so relying parties can persist
  only opaque transaction correlation context; PKCE verifier and nonce remain
  server-side and never enter application persistence or redirects.
- Included the consumed transaction context in the completed authorization
  result, enabling durable callback reconciliation without reconstructing OIDC
  protocol state in each application.

## 2.0.0 (unreleased)

- Renamed the Laravel adapter to `novvor/identity-laravel`.
- Added fail-closed explicit OIDC configuration and a production host gate.
- Added encrypted, bounded, one-time authorization transactions.
- Added the governed high-assurance PKCE + PAR + JARM + DPoP +
  private_key_jwt orchestration.
- Bound typed refresh, UserInfo, introspection, revocation and validation
  clients from `novvor/identity-sdk-php`.

## 1.1.3 - Unreleased

- Require explicit Identity error-surface configuration; no production host is
  hardcoded by the package.
- Document the private distribution and package-boundary policy.

## 1.1.2

- Added token-policy and session-mapper extension points.
- Hardened JWT payload validation and JWKS refresh behavior.
