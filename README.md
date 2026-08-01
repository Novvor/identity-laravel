# Novvor Identity Laravel

Adaptador oficial de Laravel para integrar aplicaciones con Novvor Cloud
Identity sin reconstruir OAuth/OIDC en cada producto.

El paquete se llama `novvor/identity-laravel`. La criptografía y el protocolo
viven en `novvor/identity-sdk-php`; este adaptador aporta configuración,
contenedor Laravel y una transacción de autorización de un solo uso.

## Perfil de seguridad

El perfil `novvor-high-assurance-v1` exige conjuntamente:

- Authorization Code Flow;
- PKCE S256;
- PAR (RFC 9126);
- JARM (`query.jwt`);
- DPoP (RFC 9449) con clave ES256 distinta por sesión;
- `state`, `nonce` y RFC 9207 `iss`;
- `redirect_uri` exacta;
- `private_key_jwt` para el cliente backend;
- validación RS256 de ID Token y vinculación `sub` con UserInfo.

No existe degradación automática a un flujo más débil. Si Discovery no prueba
el perfil solicitado, el inicio falla cerrado antes de redirigir al navegador.

## Instalación

La línea 2.5 se instalará íntegramente desde Packagist una vez que el núcleo
`novvor/identity-sdk-php:^2.5` tenga una etiqueta estable. No requiere
repositorios VCS, tokens de GitHub ni ramas de desarrollo.

```bash
composer require novvor/identity-laravel:^2.5 novvor/identity-sdk-php:^2.5
php artisan vendor:publish --tag=novvor-identity-config
```

Variables mínimas:

```dotenv
IDENTITY_ENABLED=true
IDENTITY_VALIDATE_ON_BOOT=true
IDENTITY_OIDC_PROFILE=novvor-high-assurance-v1
IDENTITY_OIDC_ISSUER=https://identity.example.com
IDENTITY_OIDC_CLIENT_ID=my-backend
IDENTITY_OIDC_REDIRECT_URI=https://app.example.com/auth/identity/callback
IDENTITY_OIDC_AUTHORIZATION_ENDPOINT=https://identity.example.com/oauth/authorize
IDENTITY_OIDC_TOKEN_ENDPOINT=https://identity.example.com/oauth/token
IDENTITY_OIDC_JWKS_URI=https://identity.example.com/.well-known/jwks.json
IDENTITY_OIDC_USERINFO_ENDPOINT=https://identity.example.com/oauth/userinfo
IDENTITY_OIDC_CLIENT_AUTH_METHOD=private_key_jwt
IDENTITY_OIDC_PRIVATE_KEY_ID=my-backend-key-2026-01
IDENTITY_OIDC_PRIVATE_KEY="secret reference supplied by the runtime"
IDENTITY_OIDC_INTENT_CACHE_STORE=redis
IDENTITY_OIDC_INTENT_LOCK_SECONDS=5
```

No derive endpoints desde `APP_URL`, el `Host` del request ni concatenaciones.
En producción, el boot gate rechaza hosts `.test`, `.local` y `localhost`.

## Flujo Laravel recomendado

```php
use Illuminate\Http\Request;
use Novvor\Identity\Oidc\IdentityAuthorizationManager;

final class IdentityLoginController
{
    public function redirect(Request $request, IdentityAuthorizationManager $identity)
    {
        $url = $identity->begin(
            $request->session(),
            (string) $request->attributes->get('correlation_id'),
        );

        return redirect()->away($url);
    }

    public function callback(Request $request, IdentityAuthorizationManager $identity)
    {
        $result = $identity->complete(
            $request->session(),
            $request->query(),
            (string) $request->attributes->get('correlation_id'),
        );

        $request->session()->regenerate();

        // Mapear subject, tenant y roles mediante una política de la aplicación.
        // Nunca guardar access/id/refresh tokens completos en logs.
        return redirect()->intended('/manage');
    }
}
```

`IdentityAuthorizationManager`:

- mantiene hasta cinco inicios concurrentes para pestañas distintas;
- conserva en la sesión del navegador únicamente handles opacos sin secretos;
- conserva `state`, `nonce`, PKCE verifier, return path y material privado
  DPoP cifrados del lado servidor;
- exige un cache compartido con locks atómicos para consumir cada intención una
  sola vez; en producción debe ser el store configurado para
  `IDENTITY_OIDC_INTENT_CACHE_STORE`;
- limita las transacciones a diez minutos;
- consume la transacción antes del intercambio para impedir replay;
- compara Discovery con los endpoints configurados;
- usa PAR antes de exponer la URL al navegador;
- exige JARM en high assurance;
- valida ID Token y UserInfo antes de devolver identidad.

La aplicación consumidora sigue siendo responsable de autorización, tenant
binding, role mapping, creación de sesión y logout local.

## Intenciones de inicio 2.5

La transacción de autorización no se puede reconstruir desde cookies ni desde
parámetros recibidos por el navegador. El core crea una intención durable,
ligada al identificador de sesión del navegador y al correlation ID. El
adaptador la cifra en cache, la recupera únicamente para validar la respuesta y
la consume mediante lock antes del intercambio de código.

No use `array`, `file` ni un cache local por proceso en producción: varios
workers perderían la intención o no podrían proteger el consumo simultáneo.
Use Redis u otro store compartido de Laravel con locks atómicos, y configure un
TTL de lock entre 1 y 30 segundos. Si el store no satisface ese contrato, el
boot de producción falla cerrado.

## Refresh, revocación e introspección

El contenedor expone:

- `RefreshTokenClient`;
- `TokenRevocationClient`;
- `TokenIntrospectionClient`;
- `UserInfoClient`;
- `IdTokenValidator`.

El refresh client rechaza respuestas que no roten el refresh token. Los tokens
son credenciales: no deben persistirse en logs, excepciones, telemetry ni URLs.

## DPoP nonce

El core acepta un nonce explícito para token y UserInfo. Ante
`use_dpop_nonce`, reintenta exactamente una vez con el nonce emitido por el
servidor en el intercambio de código, refresh y UserInfo. Una respuesta
malformada o un segundo desafío falla cerrado.

## Superficie de errores

`IdentityErrorSurfaceRedirector` permite delegar mensajes sanitizados a Identity.
Nunca incluir tokens, secrets, authorization codes, OTP/MFA, cookies o stack
traces en el mensaje.

## Paquetes de la familia

| Paquete | Responsabilidad |
|---|---|
| `novvor/identity-contracts` | Claims y perfiles estables, sin transporte |
| `novvor/identity-sdk-php` | OAuth/OIDC core independiente del framework |
| `novvor/identity-laravel` | Integración oficial para Laravel |
| `novvor/identity-admin-sdk-php` | Control administrativo privilegiado |
| `novvor/identity-sdk-testing` | Fakes y fixtures públicos sin secretos |

Las operaciones administrativas no pertenecen al SDK de relying party.

## Estado

La integración 2.5 requiere releases estables y compatibles tanto del núcleo
como de este adaptador. Los gates del paquete prueban el contrato local, pero
no equivalen a certificación OpenID, staging ni readiness productiva del
servidor Identity. Consulte `COMPATIBILITY.md`, `SECURITY.md` y `UPGRADING.md`.
