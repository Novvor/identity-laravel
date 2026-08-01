<?php

namespace Novvor\Identity\Tests;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Encryption\Encrypter;
use Novvor\Identity\Oidc\LaravelCacheLoginIntentStore;
use Novvor\Identity\Oidc\LaravelDpopIntentMaterialStore;
use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\LoginIntent;
use PHPUnit\Framework\TestCase;

final class LaravelLoginIntentStoresTest extends TestCase
{
    public function test_login_intent_is_encrypted_server_side_and_consumed_once(): void
    {
        $cache = new Repository(new ArrayStore());
        $store = new LaravelCacheLoginIntentStore($cache, new Encrypter(random_bytes(32), 'AES-256-GCM'));
        $intent = $this->intent();

        $store->put($intent);

        $raw = $cache->get('novvor:identity:oidc:intent:'.hash('sha256', $intent->handle));
        self::assertIsString($raw);
        self::assertStringNotContainsString($intent->codeVerifier, $raw);
        self::assertStringNotContainsString($intent->state, $raw);

        self::assertEquals($intent, $store->get($intent->handle));
        self::assertEquals($intent, $store->consume($intent->handle));
        self::assertNull($store->get($intent->handle));
        self::assertNull($store->consume($intent->handle));
    }

    public function test_dpop_private_material_is_consumed_once_outside_browser_session(): void
    {
        $cache = new Repository(new ArrayStore());
        $store = new LaravelDpopIntentMaterialStore($cache, new Encrypter(random_bytes(32), 'AES-256-GCM'));
        $key = DpopKey::generateEs256();
        $handle = $this->intent()->handle;

        $store->put($handle, $key, time() + 120);

        $raw = $cache->get('novvor:identity:oidc:dpop:'.hash('sha256', $handle));
        self::assertIsString($raw);
        self::assertStringNotContainsString($key->privateKey, $raw);

        $consumed = $store->consume($handle);
        self::assertNotNull($consumed);
        self::assertSame($key->publicJwk, $consumed->publicJwk);
        self::assertNull($store->consume($handle));
    }

    private function intent(): LoginIntent
    {
        return new LoginIntent(
            handle: rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
            state: 'state-value',
            nonce: 'nonce-value',
            codeVerifier: str_repeat('a', 43),
            returnPath: '/manage',
            browserBinding: hash('sha256', 'browser-session'),
            correlationId: 'correlation-id',
            createdAt: time(),
            expiresAt: time() + 120,
        );
    }
}
