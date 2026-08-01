<?php

namespace Novvor\Identity\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Novvor\Identity\Oidc\IdentityAuthorizationManager;
use Novvor\Identity\Oidc\LaravelCacheLoginIntentStore;
use Novvor\Identity\Oidc\LaravelDpopIntentMaterialStore;
use Novvor\IdentitySdk\Oidc\AuthorizationCodeClient;
use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\AuthorizationResponseProcessor;
use Novvor\IdentitySdk\Oidc\EnterpriseProfileValidator;
use Novvor\IdentitySdk\Oidc\IdTokenValidator;
use Novvor\IdentitySdk\Oidc\JarmAuthorizationResponseValidator;
use Novvor\IdentitySdk\Oidc\LoginIntentManager;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryClient;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\PushedAuthorizationClient;
use Novvor\IdentitySdk\Oidc\UserInfoClient;
use PHPUnit\Framework\TestCase;

final class IdentityAuthorizationManagerTest extends TestCase
{
    public function test_standard_flow_keeps_only_opaque_intent_handles_in_browser_session(): void
    {
        $manager = $this->manager([
            $this->discovery(),
            $this->discovery(),
        ]);
        $session = $this->session();

        $first = $manager->begin($session, 'correlation-1');
        $second = $manager->begin($session, 'correlation-2');

        self::assertStringStartsWith('https://identity.example.com/oauth/authorize?', $first);
        self::assertNotSame($first, $second);
        $handles = $session->get('_novvor_identity_oidc_intent_handles_v25');
        self::assertIsArray($handles);
        self::assertCount(2, $handles);
        foreach ($handles as $handle) {
            self::assertIsString($handle);
            self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43,128}$/', $handle);
        }
        self::assertNull($session->get('_novvor_identity_oidc_transactions_v2'));
    }

    public function test_high_assurance_flow_uses_par_and_never_leaks_parameters_to_browser_url(): void
    {
        $manager = $this->manager([
            $this->discovery(highAssurance: true),
            new Response(201, ['Content-Type' => 'application/json'], json_encode([
                'request_uri' => 'urn:ietf:params:oauth:request_uri:request-123',
                'expires_in' => 90,
            ], JSON_THROW_ON_ERROR)),
        ], highAssurance: true);

        $url = $manager->begin($this->session(), 'correlation-1');

        self::assertSame(
            'https://identity.example.com/oauth/authorize?client_id=backend&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Arequest-123',
            $url,
        );
        self::assertStringNotContainsString('code_challenge', $url);
        self::assertStringNotContainsString('state=', $url);
    }

    public function test_callback_without_an_active_transaction_fails_closed(): void
    {
        $manager = $this->manager([]);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('active one-time transaction');

        $manager->complete($this->session(), [
            'code' => 'unexpected-code',
            'state' => 'attacker-state',
            'iss' => 'https://identity.example.com',
        ]);
    }

    private function manager(array $responses, bool $highAssurance = false): IdentityAuthorizationManager
    {
        $http = new Client(['handler' => HandlerStack::create(new MockHandler($responses))]);
        $configuration = new OidcClientConfiguration(
            issuer: 'https://identity.example.com',
            clientId: 'backend',
            redirectUri: 'https://app.example.com/callback',
            authorizationEndpoint: 'https://identity.example.com/oauth/authorize',
            tokenEndpoint: 'https://identity.example.com/oauth/token',
            jwksUri: 'https://identity.example.com/.well-known/jwks.json',
            clientAuthenticationMethod: $highAssurance ? 'private_key_jwt' : 'none',
            privateKey: $highAssurance ? $this->privateKey() : null,
            privateKeyId: $highAssurance ? 'backend-key-1' : null,
            profile: $highAssurance ? 'novvor-high-assurance-v1' : 'standard',
            userinfoEndpoint: 'https://identity.example.com/oauth/userinfo',
        );
        $jarm = new JarmAuthorizationResponseValidator($http);

        $cache = new Repository(new ArrayStore());
        $encrypter = new Encrypter(random_bytes(32), 'AES-256-GCM');
        $intentStore = new LaravelCacheLoginIntentStore($cache, $encrypter);

        return new IdentityAuthorizationManager(
            configuration: $configuration,
            discoveryClient: new OidcDiscoveryClient($http),
            profileValidator: new EnterpriseProfileValidator(),
            requests: new AuthorizationRequestFactory(),
            par: new PushedAuthorizationClient($http),
            responses: new AuthorizationResponseProcessor($jarm),
            codes: new AuthorizationCodeClient($http),
            idTokens: new IdTokenValidator($http),
            userInfo: new UserInfoClient($http),
            intents: new LoginIntentManager($intentStore),
            intentStore: $intentStore,
            dpopMaterials: new LaravelDpopIntentMaterialStore($cache, $encrypter),
        );
    }

    private function discovery(bool $highAssurance = false): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'issuer' => 'https://identity.example.com',
            'authorization_endpoint' => 'https://identity.example.com/oauth/authorize',
            'token_endpoint' => 'https://identity.example.com/oauth/token',
            'jwks_uri' => 'https://identity.example.com/.well-known/jwks.json',
            'userinfo_endpoint' => 'https://identity.example.com/oauth/userinfo',
            'pushed_authorization_request_endpoint' => $highAssurance
                ? 'https://identity.example.com/oauth/par'
                : null,
            'response_modes_supported' => $highAssurance ? ['query', 'query.jwt'] : ['query'],
            'token_endpoint_auth_methods_supported' => $highAssurance ? ['private_key_jwt'] : ['none'],
            'dpop_signing_alg_values_supported' => $highAssurance ? ['ES256'] : [],
            'authorization_response_iss_parameter_supported' => true,
        ], JSON_THROW_ON_ERROR));
    }

    private function session(): Store
    {
        return new Store('identity-test', new ArraySessionHandler(1200));
    }

    private function privateKey(): string
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($resource);
        self::assertTrue(openssl_pkey_export($resource, $privateKey));

        return $privateKey;
    }
}
