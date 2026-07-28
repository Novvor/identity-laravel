<?php

namespace Novvor\Identity\Oidc;

use Novvor\IdentitySdk\Oidc\DpopKey;
use Novvor\IdentitySdk\Oidc\OidcTokenSet;
use Novvor\IdentitySdk\Oidc\UserInfoResponse;

final readonly class IdentityAuthorizationResult
{
    /**
     * @param array<string, mixed> $idTokenClaims
     */
    public function __construct(
        public OidcTokenSet $tokens,
        public array $idTokenClaims,
        public ?UserInfoResponse $userInfo,
        public ?DpopKey $dpopKey,
    ) {
    }
}
