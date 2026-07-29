<?php

namespace Novvor\Identity\Oidc;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Session\Session;
use Novvor\IdentitySdk\Oidc\AuthorizationCodeClient;
use Novvor\IdentitySdk\Oidc\AuthorizationRequestFactory;
use Novvor\IdentitySdk\Oidc\AuthorizationResponseProcessor;
use Novvor\IdentitySdk\Oidc\AuthorizationTransaction;
use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\EnterpriseProfileValidator;
use Novvor\IdentitySdk\Oidc\IdTokenValidator;
use Novvor\IdentitySdk\Oidc\OidcClientConfiguration;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryClient;
use Novvor\IdentitySdk\Oidc\OidcDiscoveryDocument;
use Novvor\IdentitySdk\Oidc\OidcException;
use Novvor\IdentitySdk\Oidc\PushedAuthorizationClient;
use Novvor\IdentitySdk\Oidc\UserInfoClient;
use Throwable;

final class IdentityAuthorizationManager
{
    private const SESSION_KEY = '_novvor_identity_oidc_transactions_v2';

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
        private readonly Encrypter $encrypter,
        private readonly int $transactionTtlSeconds = 600,
        private readonly int $maxPendingTransactions = 5,
    ) {
        if ($transactionTtlSeconds < 60 || $transactionTtlSeconds > 900) {
            throw new OidcException('OIDC transaction TTL must be between 60 and 900 seconds.');
        }
        if ($maxPendingTransactions < 1 || $maxPendingTransactions > 10) {
            throw new OidcException('Pending OIDC transactions must be between one and ten.');
        }
    }

    public function begin(
        Session $session,
        ?string $correlationId = null,
        ?string $requiredAcr = null,
        ?int $maxAge = null,
    ): string {
        $discovery = $this->verifiedDiscovery($correlationId);
        $transaction = $this->requests->transaction($this->configuration, $requiredAcr, $maxAge);
        $dpopKey = $this->configuration->profile === 'novvor-high-assurance-v1'
            ? DpopKey::generateEs256()
            : null;

        $this->store($session, $transaction, $dpopKey);

        if ($this->configuration->profile === 'novvor-high-assurance-v1') {
            $endpoint = $discovery->pushedAuthorizationRequestEndpoint;
            if ($endpoint === null) {
                throw new OidcException('High-assurance authorization requires a discovered PAR endpoint.');
            }
            $pushed = $this->par->push($this->configuration, $transaction, $endpoint, $correlationId);

            return $this->requests->pushedAuthorizationUrl($this->configuration, $pushed->requestUri);
        }

        return $this->configuration->authorizationEndpoint.'?'.http_build_query($transaction->parameters);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    public function complete(
        Session $session,
        array $parameters,
        ?string $correlationId = null,
    ): IdentityAuthorizationResult {
        $records = $this->records($session);
        $matchedIndex = null;
        $authorization = null;
        $record = null;

        foreach ($records as $index => $candidate) {
            try {
                $processed = $this->responses->process(
                    $this->configuration,
                    $parameters,
                    $candidate['transaction']['state'],
                    $correlationId,
                );
            } catch (Throwable) {
                continue;
            }
            $matchedIndex = $index;
            $authorization = $processed;
            $record = $candidate;
            break;
        }

        if ($matchedIndex === null || $authorization === null || $record === null) {
            throw new OidcException('Authorization response does not match an active one-time transaction.');
        }

        unset($records[$matchedIndex]);
        $this->writeRecords($session, array_values($records));

        if ($authorization->error !== null || $authorization->code === null) {
            throw new OidcException('Authorization server rejected the login request.');
        }

        $dpopKey = $this->restoreDpopKey($record['dpop_key'] ?? null);
        $tokens = $this->codes->exchange(
            $this->configuration,
            $authorization->code,
            $record['transaction']['code_verifier'],
            $correlationId,
            $dpopKey,
        );
        if ($tokens->idToken === null) {
            throw new OidcException('OIDC token response is missing the required ID token.');
        }

        $claims = $this->idTokens->validate(
            $this->configuration,
            $tokens->idToken,
            $record['transaction']['nonce'],
            $correlationId,
        );
        $subject = is_string($claims['sub'] ?? null) ? $claims['sub'] : '';
        $userInfo = $this->configuration->userinfoEndpoint === null
            ? null
            : $this->userInfo->fetch(
                $this->configuration,
                $tokens->accessToken,
                $tokens->tokenType,
                $subject,
                $correlationId,
                $dpopKey,
            );

        return new IdentityAuthorizationResult($tokens, $claims, $userInfo, $dpopKey);
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

    private function store(Session $session, AuthorizationTransaction $transaction, ?DpopKey $dpopKey): void
    {
        $records = $this->records($session);
        $records[] = [
            'created_at' => time(),
            'transaction' => $transaction->toArray(),
            'dpop_key' => $dpopKey === null ? null : [
                'private_key' => $dpopKey->privateKey,
                'public_jwk' => $dpopKey->publicJwk,
                'algorithm' => $dpopKey->algorithm,
            ],
        ];
        $this->writeRecords($session, array_slice($records, -$this->maxPendingTransactions));
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function records(Session $session): array
    {
        $encrypted = $session->get(self::SESSION_KEY);
        if (! is_string($encrypted) || $encrypted === '') {
            return [];
        }
        try {
            $records = $this->encrypter->decrypt($encrypted);
        } catch (Throwable) {
            $session->forget(self::SESSION_KEY);

            return [];
        }
        if (! is_array($records)) {
            return [];
        }

        return array_values(array_filter($records, fn (mixed $record): bool => $this->validRecord($record)));
    }

    private function validRecord(mixed $record): bool
    {
        return is_array($record)
            && is_int($record['created_at'] ?? null)
            && $record['created_at'] >= time() - $this->transactionTtlSeconds
            && is_array($record['transaction'] ?? null)
            && is_string($record['transaction']['state'] ?? null)
            && is_string($record['transaction']['nonce'] ?? null)
            && is_string($record['transaction']['code_verifier'] ?? null);
    }

    /**
     * @param list<array<string, mixed>> $records
     */
    private function writeRecords(Session $session, array $records): void
    {
        if ($records === []) {
            $session->forget(self::SESSION_KEY);

            return;
        }
        $session->put(self::SESSION_KEY, $this->encrypter->encrypt($records));
    }

    private function restoreDpopKey(mixed $payload): ?DpopKey
    {
        if ($payload === null) {
            return null;
        }
        if (! is_array($payload)
            || ! is_string($payload['private_key'] ?? null)
            || ! is_array($payload['public_jwk'] ?? null)
            || ! is_string($payload['algorithm'] ?? null)) {
            throw new OidcException('Stored DPoP transaction material is invalid.');
        }

        return new DpopKey($payload['private_key'], $payload['public_jwk'], $payload['algorithm']);
    }
}
