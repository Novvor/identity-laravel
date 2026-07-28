<?php

namespace Novvor\Identity;

use InvalidArgumentException;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;

final class OidcConfigurationFactory
{
    /**
     * @param array<string, mixed> $config
     */
    public function fromArray(array $config): OidcClientConfiguration
    {
        $privateKey = $this->optionalString($config, 'private_key');
        if ($privateKey !== null) {
            $privateKey = str_replace('\n', "\n", $privateKey);
        }

        return new OidcClientConfiguration(
            issuer: $this->requiredString($config, 'issuer'),
            clientId: $this->requiredString($config, 'client_id'),
            redirectUri: $this->requiredString($config, 'redirect_uri'),
            authorizationEndpoint: $this->requiredString($config, 'authorization_endpoint'),
            tokenEndpoint: $this->requiredString($config, 'token_endpoint'),
            jwksUri: $this->requiredString($config, 'jwks_uri'),
            clientSecret: $this->optionalString($config, 'client_secret'),
            httpTimeoutSeconds: (int) ($config['http_timeout_seconds'] ?? 5),
            clientAuthenticationMethod: (string) ($config['client_authentication_method'] ?? 'none'),
            privateKey: $privateKey,
            privateKeyId: $this->optionalString($config, 'private_key_id'),
            scopes: $this->stringList($config['scopes'] ?? ['openid', 'profile', 'email']),
            profile: (string) ($config['profile'] ?? 'standard'),
            userinfoEndpoint: $this->optionalString($config, 'userinfo_endpoint'),
            introspectionEndpoint: $this->optionalString($config, 'introspection_endpoint'),
            revocationEndpoint: $this->optionalString($config, 'revocation_endpoint'),
            jwksCacheTtlSeconds: (int) ($config['jwks_cache_ttl_seconds'] ?? 300),
        );
    }

    public function assertProductionSafe(OidcClientConfiguration $configuration): void
    {
        foreach ([
            $configuration->issuer,
            $configuration->redirectUri,
            $configuration->authorizationEndpoint,
            $configuration->tokenEndpoint,
            $configuration->jwksUri,
            $configuration->userinfoEndpoint,
            $configuration->introspectionEndpoint,
            $configuration->revocationEndpoint,
        ] as $url) {
            if ($url === null) {
                continue;
            }
            $host = strtolower((string) parse_url($url, PHP_URL_HOST));
            if ($host === '' || $host === 'localhost' || str_ends_with($host, '.test') || str_ends_with($host, '.local')) {
                throw new InvalidArgumentException('Production Identity configuration contains a development-only host.');
            }
        }
        if ($configuration->clientAuthenticationMethod === 'none'
            && $configuration->profile === 'novvor-high-assurance-v1') {
            throw new InvalidArgumentException('Production high-assurance clients require private_key_jwt.');
        }
    }

    /** @param array<string, mixed> $config */
    private function requiredString(array $config, string $key): string
    {
        $value = $this->optionalString($config, $key);
        if ($value === null) {
            throw new InvalidArgumentException("Identity configuration [{$key}] is required.");
        }

        return $value;
    }

    /** @param array<string, mixed> $config */
    private function optionalString(array $config, string $key): ?string
    {
        $value = $config[$key] ?? null;

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (is_string($value)) {
            $value = preg_split('/[\s,]+/', trim($value)) ?: [];
        }
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidArgumentException('Identity scopes must be a list.');
        }
        $scopes = [];
        foreach ($value as $scope) {
            if (! is_string($scope) || trim($scope) === '') {
                throw new InvalidArgumentException('Identity scopes contain an invalid value.');
            }
            $scopes[] = trim($scope);
        }

        return $scopes;
    }
}
