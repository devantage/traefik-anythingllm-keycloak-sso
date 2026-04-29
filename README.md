# Traefik AnythingLLM Keycloak SSO

Traefik middleware plugin that authenticates AnythingLLM users with Keycloak over OIDC.

## Flow

1. Unauthenticated requests are redirected to the Keycloak authorization endpoint. The plugin also exposes an explicit `loginPath` (default `/sso/login`) that triggers the same login flow used when the session cookie expires.
2. Traefik receives the OIDC callback at `callbackPath`.
3. The plugin exchanges the authorization code for an access token.
4. The plugin calls the Keycloak `userinfo` endpoint and extracts the username claim.
5. The plugin looks up the user in AnythingLLM and can create it automatically when enabled.
6. The plugin requests a temporary login URL from AnythingLLM using `/api/v1/users/{id}/issue-auth-token`.
7. If `anythingLLMDefaultWorkspaceSlugs` is configured, the plugin ensures the user belongs to those workspaces before issuing the login token.
8. The browser is redirected to the `loginPath` returned by AnythingLLM, which lands the user on the AnythingLLM root.

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
      version: v1.0.1
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
      anythingLLMBaseURL: http://anythingllm.cognitio.svc.cluster.local:3001
      anythingLLMPublicBaseURL: https://anythingllm.example.com
      anythingLLMApiKey: ANYTHINGLLM_API_KEY
      sessionSecret: TRAEFIK_ANYTHINGLLM_SESSION_SECRET
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
      anythingLLMDefaultWorkspaceSlugs:
        - onboarding
        - company-docs
      callbackPath: /sso/callback
      loginPath: /sso/login
      logoutPath: /sso/logout
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
      keycloakClientSecretEnv: KEYCLOAK_CLIENT_SECRET_ENV
      anythingLLMBaseURL: http://anythingllm.cognitio.svc.cluster.local:3001
      anythingLLMPublicBaseURL: https://anythingllm.example.com
      anythingLLMApiKeyEnv: ANYTHINGLLM_API_KEY_ENV
      sessionSecretEnv: TRAEFIK_ANYTHINGLLM_SESSION_SECRET_ENV
      keycloakScopes: openid profile email
      keycloakUsernameClaim: preferred_username
      keycloakEmailClaim: email
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
      anythingLLMDefaultWorkspaceSlugs:
        - onboarding
        - company-docs
      callbackPath: /sso/callback
      loginPath: /sso/login
      logoutPath: /sso/logout
      sessionCookieName: _anythingllm_keycloak_sso
      sessionCookieSecure: true
      sessionTTLSeconds: 3600
```

## Configuration Parameters

| Name                                | Description                                                                                            | Required    | Default                     | Notes                                                                                                                         |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `keycloakIssuerURL`                 | Base issuer URL for the Keycloak realm. Used to build the auth, token, userinfo, and logout endpoints. | Yes         | None                        | Example: `https://keycloak.example.com/realms/example`                                                                        |
| `keycloakClientId`                  | OIDC client ID registered in Keycloak.                                                                 | Yes         | None                        | Serialized as `keycloakClientId`                                                                                              |
| `keycloakClientSecret`              | OIDC client secret provided directly in the middleware configuration.                                  | Conditional | None                        | Required if `keycloakClientSecretEnv` is not set or resolves to an empty value                                                |
| `keycloakClientSecretEnv`           | Environment variable name that contains the OIDC client secret.                                        | Conditional | None                        | Takes precedence over `keycloakClientSecret` when both are present                                                            |
| `keycloakScopes`                    | Space-separated OAuth scopes requested during login.                                                   | No          | `openid profile email`      | Sent as the `scope` parameter to Keycloak                                                                                     |
| `keycloakUsernameClaim`             | Claim used to extract the AnythingLLM username from Keycloak `userinfo`.                               | No          | `preferred_username`        | If empty or missing, the plugin falls back to email and then `sub`                                                            |
| `keycloakEmailClaim`                | Claim used to read the email from Keycloak `userinfo`.                                                 | No          | `email`                     | Used as fallback when the username claim is empty                                                                             |
| `anythingLLMBaseURL`        | Base URL the middleware uses for outbound API calls to AnythingLLM (user lookup, user creation, and token issuance). | Yes | None                        | Should point to a private/internal address (e.g. a cluster-local Service) so the middleware's own requests are not routed back through Traefik |
| `anythingLLMPublicBaseURL`          | Public base URL used to build the OIDC `redirect_uri`, the post-login browser redirect, and the post-logout redirect. | No | Falls back to `anythingLLMBaseURL` | Set this whenever the public AnythingLLM URL differs from the internal one (almost always the case in production) |
| `anythingLLMApiKey`                 | AnythingLLM API key provided directly in the middleware configuration.                                 | Conditional | None                        | Required if `anythingLLMApiKeyEnv` is not set or resolves to an empty value                                                   |
| `anythingLLMApiKeyEnv`              | Environment variable name that contains the AnythingLLM API key.                                       | Conditional | None                        | Takes precedence over `anythingLLMApiKey` when both are present                                                               |
| `anythingLLMCreateUsers`            | Automatically creates the AnythingLLM user when it does not already exist.                             | No          | `true`                      | When `false`, authentication fails if the user is missing                                                                     |
| `anythingLLMDefaultRole`            | Role assigned to automatically created AnythingLLM users.                                              | No          | `default`                   | Sent to `/api/v1/admin/users/new`                                                                                             |
| `anythingLLMDefaultWorkspacesSlugs` | Workspace slugs that should always be assigned to authenticated users.                                 | No          | None                        | Applied to both new and pre-existing users without removing existing members                                                  |
| `callbackPath`                      | Path where Traefik receives the OIDC callback from Keycloak.                                           | No          | `/sso/callback`             | If configured without a leading slash, the plugin adds it                                                                     |
| `loginPath`                         | Path intercepted by the middleware to start the OIDC login flow regardless of authentication state.   | No          | `/sso/login`                | Triggers the same login flow used when the session cookie expires                                                             |
| `logoutPath`                        | Path intercepted by the middleware to clear the session cookie and redirect to Keycloak logout.        | No          | `/sso/logout`               | If configured without a leading slash, the plugin adds it                                                                     |
| `sessionCookieName`                 | Name of the signed session cookie created by the middleware.                                           | No          | `_anythingllm_keycloak_sso` | The plugin also uses `<sessionCookieName>_state` during login; changing `keycloakUsernameClaim` invalidates existing sessions |
| `sessionCookieSecure`               | Marks the middleware cookies as `Secure`.                                                              | No          | `true`                      | Applies to both session and state cookies                                                                                     |
| `sessionSecret`                     | Secret used to sign middleware cookies.                                                                | Conditional | None                        | Required if `sessionSecretEnv` is not set or resolves to an empty value                                                       |
| `sessionSecretEnv`                  | Environment variable name that contains the session signing secret.                                    | Conditional | None                        | Takes precedence over `sessionSecret` when both are present                                                                   |
| `sessionTTLSeconds`                 | Lifetime of the signed session cookie in seconds.                                                      | No          | `3600`                      | Values less than or equal to `0` are reset to `3600`                                                                          |
| `insecureSkipTLSVerify`             | Disables TLS certificate verification for outbound requests to Keycloak and AnythingLLM.               | No          | `false`                     | Intended only for controlled environments                                                                                     |
