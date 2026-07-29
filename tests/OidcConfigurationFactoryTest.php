<?php

namespace Novvor\Identity\Tests;

use InvalidArgumentException;
use Novvor\Identity\OidcConfigurationFactory;
use PHPUnit\Framework\TestCase;

final class OidcConfigurationFactoryTest extends TestCase
{
    public function test_builds_the_high_assurance_profile_without_deriving_endpoints(): void
    {
        $configuration = (new OidcConfigurationFactory())->fromArray([
            'issuer' => 'https://identity.example.com',
            'client_id' => 'backend',
            'redirect_uri' => 'https://app.example.com/callback',
            'authorization_endpoint' => 'https://identity.example.com/oauth/authorize',
            'token_endpoint' => 'https://identity.example.com/oauth/token',
            'jwks_uri' => 'https://identity.example.com/.well-known/jwks.json',
            'client_authentication_method' => 'private_key_jwt',
            'private_key' => "private\\nkey",
            'private_key_id' => 'key-1',
            'profile' => 'novvor-high-assurance-v1',
            'scopes' => 'openid profile email',
        ]);

        self::assertSame('novvor-high-assurance-v1', $configuration->profile);
        self::assertSame("private\nkey", $configuration->privateKey);
        self::assertSame(['openid', 'profile', 'email'], $configuration->scopes);
    }

    public function test_fails_closed_when_a_required_endpoint_is_missing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('[token_endpoint]');

        (new OidcConfigurationFactory())->fromArray([
            'issuer' => 'https://identity.example.com',
            'client_id' => 'backend',
            'redirect_uri' => 'https://app.example.com/callback',
            'authorization_endpoint' => 'https://identity.example.com/oauth/authorize',
            'jwks_uri' => 'https://identity.example.com/.well-known/jwks.json',
        ]);
    }

    public function test_production_gate_rejects_development_hosts(): void
    {
        $factory = new OidcConfigurationFactory();
        $configuration = $factory->fromArray([
            'issuer' => 'https://identity.enixconsole.test',
            'client_id' => 'backend',
            'redirect_uri' => 'https://app.enixconsole.test/callback',
            'authorization_endpoint' => 'https://identity.enixconsole.test/oauth/authorize',
            'token_endpoint' => 'https://identity.enixconsole.test/oauth/token',
            'jwks_uri' => 'https://identity.enixconsole.test/.well-known/jwks.json',
        ]);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('development-only host');

        $factory->assertProductionSafe($configuration);
    }
}
