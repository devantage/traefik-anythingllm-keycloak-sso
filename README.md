# Traefik AnythingLLM Keycloak SSO

Traefik middleware plugin that authenticates AnythingLLM users with Keycloak over OIDC.

## Flow

1. Unauthenticated requests are redirected to the Keycloak authorization endpoint.
2. Traefik receives the OIDC callback at `callbackPath`.
3. The plugin exchanges the authorization code for an access token.
4. The plugin calls the Keycloak `userinfo` endpoint and extracts the username claim.
5. The plugin looks up the user in AnythingLLM and can create it automatically when enabled.
6. The plugin requests a temporary login URL from AnythingLLM using `/api/v1/users/{id}/issue-auth-token`.
7. The browser is redirected to the `loginPath` returned by AnythingLLM. When the original request path is not `/`, the plugin appends `redirectTo=<original path>`.

## Requirements

- Traefik with plugin support enabled.
- Keycloak with an OIDC client configured for the Traefik callback URL.
- AnythingLLM running in multi-user mode.
- AnythingLLM onboarding already completed.
- AnythingLLM configured with `SIMPLE_SSO_ENABLED=1`.
- An AnythingLLM API key able to list users, create users, and issue temporary auth tokens.

## Installation

```yaml
experimental:
  plugins:
    anythingllmKeycloakSso:
      moduleName: github.com/devantage/traefik-anythingllm-keycloak-sso
      version: v0.1.0
```

The module name above matches the current Go module path in this repository.

## Usage

Minimal example with inline secrets:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: anythingllm-keycloak-sso
spec:
  plugin:
    anythingllmKeycloakSso:
      keycloakIssuerURL: https://keycloak.example.com/realms/example
      keycloakClientId: anythingllm
      keycloakClientSecret: KEYCLOAK_CLIENT_SECRET
      anythingLLMBaseURL: https://anythingllm.example.com
      anythingLLMApiKey: ANYTHINGLLM_API_KEY
      sessionSecret: TRAEFIK_ANYTHINGLLM_SESSION_SECRET
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
      callbackPath: /_auth/keycloak/callback
      logoutPath: /logout
      sessionCookieName: _anythingllm_keycloak_sso
      sessionCookieSecure: true
      sessionTTLSeconds: 3600
```

Alternative example using environment variables for sensitive values:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: anythingllm-keycloak-sso
spec:
  plugin:
    anythingllmKeycloakSso:
      keycloakIssuerURL: https://keycloak.example.com/realms/example
      keycloakClientId: anythingllm
      clientSecretEnv: KEYCLOAK_CLIENT_SECRET
      anythingLLMBaseURL: https://anythingllm.example.com
      anythingLLMApiKeyEnv: ANYTHINGLLM_API_KEY
      sessionSecretEnv: TRAEFIK_ANYTHINGLLM_SESSION_SECRET
      keycloakScopes: openid profile email
      keycloakUsernameClaim: preferred_username
      keycloakEmailClaim: email
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
```

## Configuration Parameters

| Name                      | Description                                                                                            | Required    | Default                     | Notes                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- | --------------------------- | --------------------------------------------------------------------------- |
| `keycloakIssuerURL`       | Base issuer URL for the Keycloak realm. Used to build the auth, token, userinfo, and logout endpoints. | Yes         | None                        | Example: `https://keycloak.example.com/realms/example`                      |
| `keycloakClientId`        | OIDC client ID registered in Keycloak.                                                                 | Yes         | None                        | Serialized as `keycloakClientId`                                            |
| `keycloakClientSecret`    | OIDC client secret provided directly in the middleware configuration.                                  | Conditional | None                        | Required if `clientSecretEnv` is not set or resolves to an empty value      |
| `keycloakClientSecretEnv` | Environment variable name that contains the OIDC client secret.                                        | Conditional | None                        | Takes precedence over `keycloakClientSecret` when both are present          |
| `keycloakScopes`          | Space-separated OAuth scopes requested during login.                                                   | No          | `openid profile email`      | Sent as the `scope` parameter to Keycloak                                   |
| `keycloakUsernameClaim`   | Claim used to extract the AnythingLLM username from Keycloak `userinfo`.                               | No          | `preferred_username`        | If empty or missing, the plugin falls back to email and then `sub`          |
| `keycloakEmailClaim`      | Claim used to read the email from Keycloak `userinfo`.                                                 | No          | `email`                     | Used as fallback when the username claim is empty                           |
| `anythingLLMBaseURL`      | Base URL of the AnythingLLM instance.                                                                  | Yes         | None                        | Used for user lookup, user creation, and token issuance                     |
| `anythingLLMApiKey`       | AnythingLLM API key provided directly in the middleware configuration.                                 | Conditional | None                        | Required if `anythingLLMApiKeyEnv` is not set or resolves to an empty value |
| `anythingLLMApiKeyEnv`    | Environment variable name that contains the AnythingLLM API key.                                       | Conditional | None                        | Takes precedence over `anythingLLMApiKey` when both are present             |
| `anythingLLMCreateUsers`  | Automatically creates the AnythingLLM user when it does not already exist.                             | No          | `true`                      | When `false`, authentication fails if the user is missing                   |
| `anythingLLMDefaultRole`  | Role assigned to automatically created AnythingLLM users.                                              | No          | `default`                   | Sent to `/api/v1/admin/users/new`                                           |
| `callbackPath`            | Path where Traefik receives the OIDC callback from Keycloak.                                           | No          | `/_auth/keycloak/callback`  | If configured without a leading slash, the plugin adds it                   |
| `logoutPath`              | Path intercepted by the middleware to clear the session cookie and redirect to Keycloak logout.        | No          | `/logout`                   | If configured without a leading slash, the plugin adds it                   |
| `sessionCookieName`       | Name of the signed session cookie created by the middleware.                                           | No          | `_anythingllm_keycloak_sso` | The plugin also uses `<sessionCookieName>_state` during login               |
| `sessionCookieSecure`     | Marks the middleware cookies as `Secure`.                                                              | No          | `true`                      | Applies to both session and state cookies                                   |
| `sessionSecret`           | Secret used to sign middleware cookies.                                                                | Conditional | None                        | Required if `sessionSecretEnv` is not set or resolves to an empty value     |
| `sessionSecretEnv`        | Environment variable name that contains the session signing secret.                                    | Conditional | None                        | Takes precedence over `sessionSecret` when both are present                 |
| `sessionTTLSeconds`       | Lifetime of the signed session cookie in seconds.                                                      | No          | `3600`                      | Values less than or equal to `0` are reset to `3600`                        |
| `insecureSkipTLSVerify`   | Disables TLS certificate verification for outbound requests to Keycloak and AnythingLLM.               | No          | `false`                     | Intended only for controlled environments                                   |

## Runtime Behavior

- Requests that already have a valid signed session cookie are forwarded to the next handler unchanged.
- Requests without a valid session are redirected to Keycloak.
- The plugin stores signed cookies using `HttpOnly`, `SameSite=Lax`, and the configured `sessionCookieSecure` flag.
- Logout clears both the session cookie and the temporary login state cookie, then redirects to the Keycloak logout endpoint.
- The post-logout redirect sent to Keycloak is always the external site root, based on forwarded host and scheme headers when present.

## AnythingLLM Endpoints Used

- `GET /api/v1/users`
- `POST /api/v1/admin/users/new`
- `GET /api/v1/users/{id}/issue-auth-token`

## Keycloak Endpoints Used

- `GET /protocol/openid-connect/auth`
- `POST /protocol/openid-connect/token`
- `GET /protocol/openid-connect/userinfo`
- `GET /protocol/openid-connect/logout`

## Notes

- This plugin builds external redirect URLs from `X-Forwarded-Proto` and `X-Forwarded-Host` when they are available.
- The current repository tests should be treated carefully as implementation hints; the code in `anythingllm_keycloak_sso.go` is the source of truth for configuration names and behavior.
