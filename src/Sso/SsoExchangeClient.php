<?php

namespace Novvor\Identity\Sso;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Novvor\Identity\IdentityConfig;

final class SsoExchangeClient
{
    public function __construct(
        private readonly IdentityConfig $config,
        private readonly ClientInterface $http,
    ) {
    }

    /**
     * @return array{access_token:string, token_type?:string, expires_in?:int}
     */
    /** @return array{access_token: string, token_type: string, expires_in: int|null} */
    public function exchange(string $code): array
    {
        if ($code === '') {
            throw new SsoException('missing_code', 422, 'Missing SSO code.');
        }

        $attempts = 0;
        $maxAttempts = 2;

        while (true) {
            $attempts++;

            try {
                $response = $this->http->request('POST', $this->config->exchangeUrl, [
                    'timeout' => $this->config->httpTimeoutSeconds,
                    'connect_timeout' => $this->config->httpTimeoutSeconds,
                    'http_errors' => false,
                    'headers' => [
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/json',
                        'X-Platform-App-Key' => $this->config->apiKey,
                    ],
                    'json' => [
                        'code' => $code,
                    ],
                ]);
            } catch (GuzzleException $e) {
                if ($attempts < $maxAttempts) {
                    usleep(200000);
                    continue;
                }

                throw new SsoException('exchange_failed', 502, 'SSO exchange failed.', $e);
            }

            $status = $response->getStatusCode();
            $body = (string) $response->getBody();
            $json = json_decode($body, true);
            $json = is_array($json) ? $json : [];

            if ($status < 200 || $status >= 300) {
                $message = is_string($json['error'] ?? null) ? (string) $json['error'] : 'Invalid or expired SSO code.';
                throw new SsoException('invalid_code', $status, $message);
            }

            $token = is_string($json['access_token'] ?? null) ? (string) $json['access_token'] : '';
            if ($token === '') {
                throw new SsoException('invalid_response', 502, 'SSO exchange response missing access_token.');
            }

            return [
                'access_token' => $token,
                'token_type' => is_string($json['token_type'] ?? null) ? (string) $json['token_type'] : 'Bearer',
                'expires_in' => is_int($json['expires_in'] ?? null) ? (int) $json['expires_in'] : null,
            ];
        }
    }
}
