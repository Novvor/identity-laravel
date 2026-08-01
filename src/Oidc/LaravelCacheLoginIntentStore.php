<?php

namespace Novvor\Identity\Oidc;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Encryption\Encrypter;
use Novvor\IdentitySdk\Oidc\LoginIntent;
use Novvor\IdentitySdk\Oidc\LoginIntentStore;
use Novvor\IdentitySdk\Oidc\OidcException;
use Throwable;

/**
 * Stores authorization transactions server-side. The browser receives only an
 * opaque handle, while the sensitive PKCE/nonce material remains encrypted at
 * rest and is consumed under a distributed cache lock.
 */
final class LaravelCacheLoginIntentStore implements LoginIntentStore
{
    public function __construct(
        private readonly Repository $cache,
        private readonly Encrypter $encrypter,
        private readonly int $lockSeconds = 5,
    ) {
        $this->lockProvider();
        if ($this->lockSeconds < 1 || $this->lockSeconds > 30) {
            throw new OidcException('OIDC login intent lock duration must be between one and thirty seconds.');
        }
    }

    public function put(LoginIntent $intent): void
    {
        $seconds = max(1, $intent->expiresAt - time());
        $this->cache->put($this->key($intent->handle), $this->encrypter->encrypt($this->payload($intent)), $seconds);
    }

    public function get(string $handle): ?LoginIntent
    {
        $encrypted = $this->cache->get($this->key($handle));
        if (! is_string($encrypted) || $encrypted === '') {
            return null;
        }

        try {
            $intent = $this->hydrate($this->encrypter->decrypt($encrypted));
        } catch (Throwable) {
            $this->cache->forget($this->key($handle));

            return null;
        }

        if ($intent->isExpired(time())) {
            $this->cache->forget($this->key($handle));

            return null;
        }

        return $intent;
    }

    public function consume(string $handle): ?LoginIntent
    {
        $lock = $this->lockProvider()->lock($this->lockKey($handle), $this->lockSeconds);
        if (! $lock->get()) {
            throw new OidcException('OIDC login transaction is already being processed.');
        }

        try {
            $intent = $this->get($handle);
            if ($intent !== null) {
                $this->cache->forget($this->key($handle));
            }

            return $intent;
        } finally {
            $lock->release();
        }
    }

    private function key(string $handle): string
    {
        return 'novvor:identity:oidc:intent:'.hash('sha256', $handle);
    }

    private function lockKey(string $handle): string
    {
        return 'novvor:identity:oidc:intent-lock:'.hash('sha256', $handle);
    }

    private function lockProvider(): LockProvider
    {
        $store = $this->cache->getStore();
        if (! $store instanceof LockProvider) {
            throw new OidcException('OIDC login intent storage requires an atomic lock-capable cache store.');
        }

        return $store;
    }

    /**
     * @return array<string, int|string>
     */
    private function payload(LoginIntent $intent): array
    {
        return [
            'v' => 1,
            'handle' => $intent->handle,
            'state' => $intent->state,
            'nonce' => $intent->nonce,
            'code_verifier' => $intent->codeVerifier,
            'return_path' => $intent->returnPath,
            'browser_binding' => $intent->browserBinding,
            'correlation_id' => $intent->correlationId,
            'created_at' => $intent->createdAt,
            'expires_at' => $intent->expiresAt,
        ];
    }

    private function hydrate(mixed $payload): LoginIntent
    {
        if (! is_array($payload) || ($payload['v'] ?? null) !== 1) {
            throw new OidcException('Stored OIDC login transaction is invalid.');
        }

        return new LoginIntent(
            handle: (string) ($payload['handle'] ?? ''),
            state: (string) ($payload['state'] ?? ''),
            nonce: (string) ($payload['nonce'] ?? ''),
            codeVerifier: (string) ($payload['code_verifier'] ?? ''),
            returnPath: (string) ($payload['return_path'] ?? ''),
            browserBinding: (string) ($payload['browser_binding'] ?? ''),
            correlationId: (string) ($payload['correlation_id'] ?? ''),
            createdAt: (int) ($payload['created_at'] ?? 0),
            expiresAt: (int) ($payload['expires_at'] ?? 0),
        );
    }
}
