# Changelog

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
