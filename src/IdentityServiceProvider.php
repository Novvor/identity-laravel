<?php

namespace Novvor\Identity;

use GuzzleHttp\Client;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\ServiceProvider;
use Novvor\Identity\Auth\IdentityErrorSurfaceRedirector;
use Novvor\Identity\Contracts\IdentitySessionMapperInterface;
use Novvor\Identity\Contracts\IdentityTokenValidationPolicyInterface;
use Novvor\Identity\Jwt\IdentityTokenValidationPolicy;
use Novvor\Identity\Jwt\JwtVerifier;
use Novvor\Identity\Oidc\IdentityAuthorizationManager;
use Novvor\Identity\Oidc\LaravelCacheLoginIntentStore;
use Novvor\Identity\Oidc\LaravelDpopIntentMaterialStore;
use Novvor\Identity\Session\IdentitySessionMapper;
use Novvor\Identity\Sso\SsoExchangeClient;
use Novvor\IdentitySdk\Oidc\AuthorizationCodeClient;
use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\AuthorizationResponseProcessor;
use Novvor\IdentitySdk\Oidc\EnterpriseProfileValidator;
use Novvor\IdentitySdk\Oidc\IdTokenValidator;
use Novvor\IdentitySdk\Oidc\JarmAuthorizationResponseValidator;
use Novvor\IdentitySdk\Oidc\LoginIntentManager;
use Novvor\IdentitySdk\Oidc\LoginIntentStore;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryClient;
use Novvor\IdentitySdk\Oidc\PushedAuthorizationClient;
use Novvor\IdentitySdk\Oidc\RefreshTokenClient;
use Novvor\IdentitySdk\Oidc\TokenIntrospectionClient;
use Novvor\IdentitySdk\Oidc\TokenRevocationClient;
use Novvor\IdentitySdk\Oidc\UserInfoClient;
use Psr\SimpleCache\CacheInterface;

final class IdentityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/identity.php', 'identity');

        $this->app->singleton(IdentityConfig::class, function (): IdentityConfig {
            $config = (array) config('identity', []);

            return new IdentityConfig(
                issuer: (string) ($config['issuer'] ?? ''),
                jwksUrl: (string) ($config['jwks_url'] ?? ''),
                exchangeUrl: (string) ($config['exchange_url'] ?? ''),
                apiKey: (string) ($config['api_key'] ?? ''),
                jwksCacheTtlSeconds: (int) ($config['jwks_cache_ttl_seconds'] ?? 300),
                clockSkewSeconds: (int) ($config['clock_skew_seconds'] ?? 30),
                httpTimeoutSeconds: (float) ($config['http_timeout_seconds'] ?? 5.0),
            );
        });

        $this->app->singleton(Client::class, function (): Client {
            return new Client([
                'allow_redirects' => false,
                'http_errors' => false,
            ]);
        });

        $this->app->singleton(OidcClientConfiguration::class, function (): OidcClientConfiguration {
            return (new OidcConfigurationFactory())->fromArray((array) config('identity.oidc', []));
        });
        $this->app->singleton(OidcDiscoveryClient::class, fn ($app): OidcDiscoveryClient => new OidcDiscoveryClient($app->make(Client::class)));
        $this->app->singleton(AuthorizationRequestFactory::class);
        $this->app->singleton(PushedAuthorizationClient::class, fn ($app): PushedAuthorizationClient => new PushedAuthorizationClient($app->make(Client::class)));
        $this->app->singleton(JarmAuthorizationResponseValidator::class, fn ($app): JarmAuthorizationResponseValidator => new JarmAuthorizationResponseValidator($app->make(Client::class)));
        $this->app->singleton(AuthorizationResponseProcessor::class, fn ($app): AuthorizationResponseProcessor => new AuthorizationResponseProcessor($app->make(JarmAuthorizationResponseValidator::class)));
        $this->app->singleton(AuthorizationCodeClient::class, fn ($app): AuthorizationCodeClient => new AuthorizationCodeClient($app->make(Client::class)));
        $this->app->singleton(RefreshTokenClient::class, fn ($app): RefreshTokenClient => new RefreshTokenClient($app->make(Client::class)));
        $this->app->singleton(UserInfoClient::class, fn ($app): UserInfoClient => new UserInfoClient($app->make(Client::class)));
        $this->app->singleton(TokenIntrospectionClient::class, fn ($app): TokenIntrospectionClient => new TokenIntrospectionClient($app->make(Client::class)));
        $this->app->singleton(TokenRevocationClient::class, fn ($app): TokenRevocationClient => new TokenRevocationClient($app->make(Client::class)));
        $this->app->singleton(IdTokenValidator::class, fn ($app): IdTokenValidator => new IdTokenValidator($app->make(Client::class)));
        $this->app->singleton(EnterpriseProfileValidator::class);
        $this->app->singleton(LaravelCacheLoginIntentStore::class, function ($app): LaravelCacheLoginIntentStore {
            return new LaravelCacheLoginIntentStore(
                cache: $this->oidcIntentCache($app->make(CacheFactory::class)),
                encrypter: $app->make('encrypter'),
                lockSeconds: (int) config('identity.oidc.intent_lock_seconds', 5),
            );
        });
        $this->app->alias(LaravelCacheLoginIntentStore::class, LoginIntentStore::class);
        $this->app->singleton(LoginIntentManager::class, fn ($app): LoginIntentManager => new LoginIntentManager(
            $app->make(LoginIntentStore::class),
            (int) config('identity.oidc.transaction_ttl_seconds', 600),
        ));
        $this->app->singleton(LaravelDpopIntentMaterialStore::class, function ($app): LaravelDpopIntentMaterialStore {
            return new LaravelDpopIntentMaterialStore(
                cache: $this->oidcIntentCache($app->make(CacheFactory::class)),
                encrypter: $app->make('encrypter'),
                lockSeconds: (int) config('identity.oidc.intent_lock_seconds', 5),
            );
        });
        $this->app->singleton(IdentityAuthorizationManager::class, fn ($app): IdentityAuthorizationManager => new IdentityAuthorizationManager(
            configuration: $app->make(OidcClientConfiguration::class),
            discoveryClient: $app->make(OidcDiscoveryClient::class),
            profileValidator: $app->make(EnterpriseProfileValidator::class),
            requests: $app->make(AuthorizationRequestFactory::class),
            par: $app->make(PushedAuthorizationClient::class),
            responses: $app->make(AuthorizationResponseProcessor::class),
            codes: $app->make(AuthorizationCodeClient::class),
            idTokens: $app->make(IdTokenValidator::class),
            userInfo: $app->make(UserInfoClient::class),
            intents: $app->make(LoginIntentManager::class),
            intentStore: $app->make(LoginIntentStore::class),
            dpopMaterials: $app->make(LaravelDpopIntentMaterialStore::class),
            maxPendingTransactions: (int) config('identity.oidc.max_pending_transactions', 5),
        ));

        $this->app->singleton(JwtVerifier::class, function ($app): JwtVerifier {
            $cache = null;
            $resolvedCache = $app->bound('cache.store') ? $app->make('cache.store') : null;
            if ($resolvedCache instanceof CacheInterface) {
                $cache = $resolvedCache;
            }

            return new JwtVerifier(
                config: $app->make(IdentityConfig::class),
                http: $app->make(Client::class),
                cache: $cache,
                tokenPolicy: $app->make(IdentityTokenValidationPolicyInterface::class),
            );
        });

        $this->app->singleton(SsoExchangeClient::class, function ($app): SsoExchangeClient {
            return new SsoExchangeClient(
                config: $app->make(IdentityConfig::class),
                http: $app->make(Client::class),
            );
        });

        $identityConfig = (array) config('identity', []);
        $tokenValidationPolicy = (string) ($identityConfig['token_validation_policy'] ?? IdentityTokenValidationPolicy::class);
        if (is_subclass_of($tokenValidationPolicy, IdentityTokenValidationPolicyInterface::class) || is_a($tokenValidationPolicy, IdentityTokenValidationPolicyInterface::class, true)) {
            $this->app->bind(IdentityTokenValidationPolicyInterface::class, $tokenValidationPolicy);
        } else {
            $this->app->bind(IdentityTokenValidationPolicyInterface::class, IdentityTokenValidationPolicy::class);
        }

        $sessionMapper = (string) ($identityConfig['session_mapper'] ?? IdentitySessionMapper::class);
        if (is_subclass_of($sessionMapper, IdentitySessionMapperInterface::class) || is_a($sessionMapper, IdentitySessionMapperInterface::class, true)) {
            $this->app->bind(IdentitySessionMapperInterface::class, $sessionMapper);
        } else {
            $this->app->bind(IdentitySessionMapperInterface::class, IdentitySessionMapper::class);
        }

        $this->app->singleton(IdentityErrorSurfaceRedirector::class);
    }

    public function boot(): void
    {
        if ((bool) config('identity.enabled', true)
            && (bool) config('identity.validate_on_boot', true)
            && $this->app->environment('production')) {
            $configuration = $this->app->make(OidcClientConfiguration::class);
            (new OidcConfigurationFactory())->assertProductionSafe($configuration);
            $this->app->make(LaravelCacheLoginIntentStore::class);
        }

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/identity.php' => config_path('identity.php'),
            ], 'novvor-identity-config');
        }
    }

    private function oidcIntentCache(CacheFactory $cacheFactory): CacheRepository
    {
        $store = config('identity.oidc.intent_cache_store');
        if ($this->app->environment('production') && (! is_string($store) || $store === '')) {
            throw new \RuntimeException('IDENTITY_OIDC_INTENT_CACHE_STORE is required in production.');
        }

        return is_string($store) && $store !== ''
            ? $cacheFactory->store($store)
            : $cacheFactory->store();
    }
}
