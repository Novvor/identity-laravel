<?php

namespace Novvor\Identity\Oidc;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Encryption\Encrypter;
use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\OidcException;
use Throwable;

/** Keeps the private DPoP key outside the browser session until callback use. */
final class LaravelDpopIntentMaterialStore
{
    public function __construct(
        private readonly Repository $cache,
        private readonly Encrypter $encrypter,
        private readonly int $lockSeconds = 5,
    ) {
        $this->lockProvider();
        if ($this->lockSeconds < 1 || $this->lockSeconds > 30) {
            throw new OidcException('OIDC DPoP material lock duration must be between one and thirty seconds.');
        }
    }

    public function put(string $intentHandle, DpopKey $key, int $expiresAt): void
    {
        $this->cache->put($this->key($intentHandle), $this->encrypter->encrypt([
            'v' => 1,
            'private_key' => $key->privateKey,
            'public_jwk' => $key->publicJwk,
            'algorithm' => $key->algorithm,
            'expires_at' => $expiresAt,
        ]), max(1, $expiresAt - time()));
    }

    public function consume(string $intentHandle): ?DpopKey
    {
        $lock = $this->lockProvider()->lock($this->lockKey($intentHandle), $this->lockSeconds);
        if (! $lock->get()) {
            throw new OidcException('OIDC DPoP transaction material is already being processed.');
        }

        try {
            $encrypted = $this->cache->pull($this->key($intentHandle));
            if (! is_string($encrypted) || $encrypted === '') {
                return null;
            }
            $payload = $this->encrypter->decrypt($encrypted);
            if (! is_array($payload)
                || ($payload['v'] ?? null) !== 1
                || ! is_string($payload['private_key'] ?? null)
                || ! is_array($payload['public_jwk'] ?? null)
                || ! is_string($payload['algorithm'] ?? null)
                || ! is_int($payload['expires_at'] ?? null)
                || $payload['expires_at'] <= time()) {
                return null;
            }

            return new DpopKey($payload['private_key'], $payload['public_jwk'], $payload['algorithm']);
        } catch (Throwable) {
            return null;
        } finally {
            $lock->release();
        }
    }

    public function forget(string $intentHandle): void
    {
        $this->cache->forget($this->key($intentHandle));
    }

    private function key(string $intentHandle): string
    {
        return 'novvor:identity:oidc:dpop:'.hash('sha256', $intentHandle);
    }

    private function lockKey(string $intentHandle): string
    {
        return 'novvor:identity:oidc:dpop-lock:'.hash('sha256', $intentHandle);
    }

    private function lockProvider(): LockProvider
    {
        $store = $this->cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new OidcException('OIDC DPoP material storage requires an atomic lock-capable cache store.');
        }

        return $store;
    }
}
