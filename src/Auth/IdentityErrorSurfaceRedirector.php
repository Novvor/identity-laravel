<?php

namespace Novvor\Identity\Auth;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Str;

final class IdentityErrorSurfaceRedirector
{
    /** @param array<string, mixed> $payload */
    public function redirect(array $payload = [], ?Request $request = null): RedirectResponse
    {
        return Redirect::away($this->url($payload, $request));
    }

    /** @param array<string, mixed> $payload */
    public function url(array $payload = [], ?Request $request = null): string
    {
        $request ??= request();

        $baseUrl = rtrim((string) config('identity.error_surface.identity_base_url', ''), '/');
        if ($baseUrl === '' || filter_var($baseUrl, FILTER_VALIDATE_URL) === false) {
            throw new \LogicException('IDENTITY_ERROR_SURFACE_BASE_URL must be configured with an absolute URL.');
        }
        $path = '/'.ltrim((string) config('identity.error_surface.path', '/auth/identity/error'), '/');
        $code = $this->safeToken((string) ($payload['code'] ?? config('identity.error_surface.default_code', 'identity_login_failed')));
        $message = $this->safeMessage((string) ($payload['message'] ?? config('identity.error_surface.default_message', 'No se pudo completar el inicio de sesión.')));
        $correlationId = trim((string) ($payload['correlation_id'] ?? $request->attributes->get('correlation_id', '')));

        return $baseUrl.$path.'?'.http_build_query(array_filter([
            'app' => $this->appKey(),
            'code' => $code,
            'message' => $message,
            'correlation_id' => $correlationId,
            'return_url' => $this->returnUrl(),
        ], static fn (string $value): bool => $value !== ''));
    }

    private function appKey(): string
    {
        return $this->safeToken((string) config('identity.error_surface.app_key', 'external-app'));
    }

    private function returnUrl(): string
    {
        $configured = trim((string) config('identity.error_surface.return_url', ''));
        if ($configured !== '') {
            return $configured;
        }

        return rtrim((string) config('app.url', ''), '/').'/login';
    }

    private function safeToken(string $value): string
    {
        $value = Str::of($value)->lower()->replaceMatches('/[^a-z0-9_.:-]/', '_')->trim('_')->toString();

        return $value !== '' ? Str::limit($value, 96, '') : 'identity_login_failed';
    }

    private function safeMessage(string $value): string
    {
        $value = trim(strip_tags($value));
        $value = preg_replace('/\s+/', ' ', $value) ?: '';

        return $value !== '' ? Str::limit($value, 420, '') : 'No se pudo completar el inicio de sesión.';
    }
}
