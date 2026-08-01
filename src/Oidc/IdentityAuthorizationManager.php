<?php

namespace Novvor\Identity\Oidc;

use Illuminate\Contracts\Session\Session;
use Novvor\IdentitySdk\Oidc\AuthorizationCodeClient;
use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\AuthorizationResponseProcessor;
use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\EnterpriseProfileValidator;
use Novvor\IdentitySdk\Oidc\IdTokenValidator;
use Novvor\IdentitySdk\Oidc\LoginIntentManager;
use Novvor\IdentitySdk\Oidc\LoginIntentStore;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryClient;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryDocument;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\PushedAuthorizationClient;
use Novvor\IdentitySdk\Oidc\UserInfoClient;
use Throwable;

/**
 * Browser-session OIDC coordinator.
 *
 * Authentication state is durable and shared-cache backed. The session carries
 * only opaque handles, so PKCE verifiers, nonces and DPoP private keys cannot
 * be replayed from a browser session payload or a different application node.
 */
final class IdentityAuthorizationManager
{
    private const SESSION_KEY = '_novvor_identity_oidc_intent_handles_v25';

    private const LEGACY_SESSION_KEY = '_novvor_identity_oidc_transactions_v2';

    public function __construct(
        private readonly OidcClientConfiguration $configuration,
        private readonly OidcDiscoveryClient $discoveryClient,
        private readonly EnterpriseProfileValidator $profileValidator,
        private readonly AuthorizationRequestFactory $requests,
        private readonly PushedAuthorizationClient $par,
        private readonly AuthorizationResponseProcessor $responses,
        private readonly AuthorizationCodeClient $codes,
        private readonly IdTokenValidator $idTokens,
        private readonly UserInfoClient $userInfo,
        private readonly LoginIntentManager $intents,
        private readonly LoginIntentStore $intentStore,
        private readonly LaravelDpopIntentMaterialStore $dpopMaterials,
        private readonly int $maxPendingTransactions = 5,
    ) {
        if ($this->maxPendingTransactions < 1 || $this->maxPendingTransactions > 10) {
            throw new OidcException('Pending OIDC transactions must be between one and ten.');
        }
    }

    public function begin(
        Session $session,
        ?string $correlationId = null,
        ?string $requiredAcr = null,
        ?int $maxAge = null,
        string $returnPath = '/',
    ): string {
        return $this->beginTransaction($session, $correlationId, $requiredAcr, $maxAge, $returnPath)->authorizationUrl;
    }

    public function beginTransaction(
        Session $session,
        ?string $correlationId = null,
        ?string $requiredAcr = null,
        ?int $maxAge = null,
        string $returnPath = '/',
    ): IdentityAuthorizationStart {
        $correlationId ??= bin2hex(random_bytes(16));
        $discovery = $this->verifiedDiscovery($correlationId);
        $transaction = $this->requests->transaction($this->configuration, $requiredAcr, $maxAge);
        $dpopKey = $this->configuration->profile === 'novvor-high-assurance-v1'
            ? DpopKey::generateEs256()
            : null;

        // Existing v2 records contain sensitive state in browser storage. They
        // cannot be safely migrated, so a new login is deliberately required.
        $session->forget(self::LEGACY_SESSION_KEY);
        $intent = $this->intents->begin(
            $transaction,
            $returnPath,
            $this->browserBinding($session),
            $correlationId,
        );
        foreach ($this->storeHandle($session, $intent->handle) as $evictedHandle) {
            $this->discard($session, $evictedHandle);
        }

        try {
            if ($dpopKey !== null) {
                $this->dpopMaterials->put($intent->handle, $dpopKey, $intent->expiresAt);
            }

            if ($this->configuration->profile === 'novvor-high-assurance-v1') {
                $endpoint = $discovery->pushedAuthorizationRequestEndpoint;
                if ($endpoint === null) {
                    throw new OidcException('High-assurance authorization requires a discovered PAR endpoint.');
                }
                $pushed = $this->par->push($this->configuration, $transaction, $endpoint, $correlationId);

                return new IdentityAuthorizationStart(
                    $this->requests->pushedAuthorizationUrl($this->configuration, $pushed->requestUri),
                    $intent->handle,
                    $intent->expiresAt,
                    $intent->correlationId,
                    $intent->returnPath,
                );
            }

            return new IdentityAuthorizationStart(
                $this->configuration->authorizationEndpoint.'?'.http_build_query($transaction->parameters),
                $intent->handle,
                $intent->expiresAt,
                $intent->correlationId,
                $intent->returnPath,
            );
        } catch (Throwable $exception) {
            $this->discard($session, $intent->handle);

            throw $exception;
        }
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public function complete(
        Session $session,
        array $parameters,
        ?string $correlationId = null,
    ): IdentityAuthorizationResult {
        $matchedHandle = null;
        $candidate = null;
        $authorization = null;

        foreach ($this->handles($session) as $handle) {
            $intent = $this->intentStore->get($handle);
            if ($intent === null) {
                $this->removeHandle($session, $handle);

                continue;
            }
            try {
                $processed = $this->responses->process(
                    $this->configuration,
                    $parameters,
                    $intent->state,
                    $correlationId ?? $intent->correlationId,
                );
            } catch (Throwable) {
                continue;
            }
            $matchedHandle = $handle;
            $candidate = $intent;
            $authorization = $processed;
            break;
        }

        if ($matchedHandle === null || $candidate === null || $authorization === null) {
            throw new OidcException('Authorization response does not match an active one-time transaction.');
        }

        try {
            $intent = $this->intents->consume($matchedHandle, $this->browserBinding($session));
        } finally {
            // The state matched a local intent. Never leave that browser handle
            // behind even if the durable consume rejects it as stale or replayed.
            $this->removeHandle($session, $matchedHandle);
        }
        if ($authorization->error !== null || $authorization->code === null) {
            $this->dpopMaterials->forget($intent->handle);

            throw new OidcException('Authorization server rejected the login request.');
        }

        $dpopKey = $this->configuration->profile === 'novvor-high-assurance-v1'
            ? $this->dpopMaterials->consume($intent->handle)
            : null;
        if ($this->configuration->profile === 'novvor-high-assurance-v1' && $dpopKey === null) {
            throw new OidcException('Stored DPoP transaction material is unavailable.');
        }

        $effectiveCorrelationId = $correlationId ?? $intent->correlationId;
        $tokens = $this->codes->exchange(
            $this->configuration,
            $authorization->code,
            $intent->codeVerifier,
            $effectiveCorrelationId,
            $dpopKey,
        );
        if ($tokens->idToken === null) {
            throw new OidcException('OIDC token response is missing the required ID token.');
        }

        $claims = $this->idTokens->validate(
            $this->configuration,
            $tokens->idToken,
            $intent->nonce,
            $effectiveCorrelationId,
        );
        $subject = $claims['sub'] ?? '';
        $userInfo = $this->configuration->userinfoEndpoint === null
            ? null
            : $this->userInfo->fetch(
                $this->configuration,
                $tokens->accessToken,
                $tokens->tokenType,
                $subject,
                $effectiveCorrelationId,
                $dpopKey,
            );

        return new IdentityAuthorizationResult(
            $tokens,
            $claims,
            $userInfo,
            $dpopKey,
            $intent->handle,
            $intent->returnPath,
            $intent->correlationId,
        );
    }

    private function verifiedDiscovery(?string $correlationId): OidcDiscoveryDocument
    {
        $discovery = $this->discoveryClient->discover(
            $this->configuration->issuer,
            $this->configuration->httpTimeoutSeconds,
            $correlationId,
        );
        foreach ([
            [$this->configuration->authorizationEndpoint, $discovery->authorizationEndpoint],
            [$this->configuration->tokenEndpoint, $discovery->tokenEndpoint],
            [$this->configuration->jwksUri, $discovery->jwksUri],
        ] as [$configured, $advertised]) {
            if (! hash_equals($configured, $advertised)) {
                throw new OidcException('Configured OIDC endpoint does not match signed deployment policy.');
            }
        }
        $this->profileValidator->assertSupported($this->configuration, $discovery);

        return $discovery;
    }

    private function browserBinding(Session $session): string
    {
        $sessionId = $session->getId();
        if ($sessionId === '') {
            throw new OidcException('OIDC authorization requires an initialized browser session.');
        }

        return $sessionId;
    }

    /**
     * @return list<string>
     */
    private function handles(Session $session): array
    {
        $handles = $session->get(self::SESSION_KEY, []);
        if (! is_array($handles)) {
            $session->forget(self::SESSION_KEY);

            return [];
        }

        return array_values(array_filter($handles, static fn (mixed $handle): bool => is_string($handle)
            && preg_match('/^[A-Za-z0-9_-]{43,128}$/', $handle) === 1));
    }

    /**
     * @return list<string> Handles evicted from the browser's bounded pending-intent list.
     */
    private function storeHandle(Session $session, string $handle): array
    {
        $handles = array_values(array_unique([...$this->handles($session), $handle]));
        $evicted = array_slice($handles, 0, max(0, count($handles) - $this->maxPendingTransactions));
        $session->put(self::SESSION_KEY, array_slice($handles, -$this->maxPendingTransactions));

        return $evicted;
    }

    private function removeHandle(Session $session, string $handle): void
    {
        $handles = array_values(array_filter(
            $this->handles($session),
            static fn (string $candidate): bool => ! hash_equals($candidate, $handle),
        ));
        if ($handles === []) {
            $session->forget(self::SESSION_KEY);

            return;
        }
        $session->put(self::SESSION_KEY, $handles);
    }

    private function discard(Session $session, string $handle): void
    {
        try {
            $this->intents->consume($handle, $this->browserBinding($session));
        } catch (Throwable) {
            // The original exception is the only safe signal for callers.
        }
        $this->dpopMaterials->forget($handle);
        $this->removeHandle($session, $handle);
    }
}
