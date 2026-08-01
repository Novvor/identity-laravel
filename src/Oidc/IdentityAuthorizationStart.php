<?php

namespace Novvor\Identity\Oidc;

/**
 * Server-side authorization hand-off.
 *
 * The handle is an opaque, high-entropy identifier. It may be persisted by a
 * relying party only as a keyed or one-way digest to correlate its own
 * application context after the SDK has atomically consumed the transaction.
 * It never contains protocol secrets such as state, nonce or the PKCE verifier.
 */
final readonly class IdentityAuthorizationStart
{
    public function __construct(
        public string $authorizationUrl,
        public string $intentHandle,
        public int $expiresAt,
        public string $correlationId,
        public string $returnPath,
    ) {
    }
}
