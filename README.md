# Traefik AnythingLLM Keycloak SSO

Traefik middleware plugin that authenticates AnythingLLM users with Keycloak over OIDC.

## Flow

0. Requests to `/api/*` bypass the middleware entirely and are forwarded straight to the AnythingLLM backend, which handles its own API authentication (Bearer tokens).
1. Unauthenticated browser navigations are redirected to the Keycloak authorization endpoint. Non-HTML requests (XHR, asset fetches, etc.) get `401 Unauthorized` instead, so failed loads are not rewritten as HTML pages. The plugin also exposes an explicit `loginPath` (default `/sso/login`) that starts the same login flow when no session exists, or redirects to the AnythingLLM root when already authenticated.
2. Traefik receives the OIDC callback at `callbackPath`.
3. The plugin exchanges the authorization code for an access token.
4. The plugin calls the Keycloak `userinfo` endpoint and extracts the username claim.
5. The plugin looks up the user in AnythingLLM and can create it automatically when enabled.
6. If `anythingLLMDefaultWorkspacesSlugs` is configured, the plugin ensures the user belongs to those workspaces.
7. The plugin requests a temporary login URL from AnythingLLM using `/api/v1/users/{id}/issue-auth-token`.
8. The browser is redirected to the `loginPath` returned by AnythingLLM, which lands the user on the AnythingLLM root.
9. When the browser later navigates to `anythingLLMLogoutDetectionPath` (the AnythingLLM-native login page, default `/login`) while still holding a valid middleware session, the plugin treats it as an AnythingLLM-side logout and either triggers a Keycloak logout or restarts the OIDC flow silently, breaking the cookie-mismatch loop.

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
      version: v1.3.0
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
      anythingLLMApiKey: ANYTHINGLLM_API_KEY
      sessionSecret: TRAEFIK_ANYTHINGLLM_SESSION_SECRET
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
      anythingLLMDefaultWorkspacesSlugs:
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
      anythingLLMApiKeyEnv: ANYTHINGLLM_API_KEY_ENV
      sessionSecretEnv: TRAEFIK_ANYTHINGLLM_SESSION_SECRET_ENV
      keycloakScopes: openid profile email
      keycloakUsernameClaim: preferred_username
      keycloakEmailClaim: email
      anythingLLMCreateUsers: true
      anythingLLMDefaultRole: default
      anythingLLMDefaultWorkspacesSlugs:
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

| Name                                | Description                                                                                                          | Required    | Default                     | Notes                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `keycloakIssuerURL`                 | Base issuer URL for the Keycloak realm. Used to build the auth, token, userinfo, and logout endpoints.               | Yes         | None                        | Example: `https://keycloak.example.com/realms/example`                                                                                                                                                                                                                                                                |
| `keycloakClientId`                  | OIDC client ID registered in Keycloak.                                                                               | Yes         | None                        | Serialized as `keycloakClientId`                                                                                                                                                                                                                                                                                      |
| `keycloakClientSecret`              | OIDC client secret provided directly in the middleware configuration.                                                | Conditional | None                        | Required if `keycloakClientSecretEnv` is not set or resolves to an empty value                                                                                                                                                                                                                                        |
| `keycloakClientSecretEnv`           | Environment variable name that contains the OIDC client secret.                                                      | Conditional | None                        | Takes precedence over `keycloakClientSecret` when both are present                                                                                                                                                                                                                                                    |
| `keycloakScopes`                    | Space-separated OAuth scopes requested during login.                                                                 | No          | `openid profile email`      | Sent as the `scope` parameter to Keycloak                                                                                                                                                                                                                                                                             |
| `keycloakUsernameClaim`             | Claim used to extract the AnythingLLM username from Keycloak `userinfo`.                                             | No          | `preferred_username`        | If empty or missing, the plugin falls back to email and then `sub`                                                                                                                                                                                                                                                    |
| `keycloakEmailClaim`                | Claim used to read the email from Keycloak `userinfo`.                                                               | No          | `email`                     | Used as fallback when the username claim is empty                                                                                                                                                                                                                                                                     |
| `anythingLLMBaseURL`                | Base URL the middleware uses for outbound API calls to AnythingLLM (user lookup, user creation, and token issuance). | Yes         | None                        | Should point to a private/internal address (e.g. a cluster-local Service) so the middleware's own requests are not routed back through Traefik. The public URL used for OIDC `redirect_uri` and post-login/logout redirects is derived from the incoming request (`X-Forwarded-Proto` / `X-Forwarded-Host` / `Host`). |
| `anythingLLMApiKey`                 | AnythingLLM API key provided directly in the middleware configuration.                                               | Conditional | None                        | Required if `anythingLLMApiKeyEnv` is not set or resolves to an empty value                                                                                                                                                                                                                                           |
| `anythingLLMApiKeyEnv`              | Environment variable name that contains the AnythingLLM API key.                                                     | Conditional | None                        | Takes precedence over `anythingLLMApiKey` when both are present                                                                                                                                                                                                                                                       |
| `anythingLLMCreateUsers`            | Automatically creates the AnythingLLM user when it does not already exist.                                           | No          | `true`                      | When `false`, authentication fails if the user is missing                                                                                                                                                                                                                                                             |
| `anythingLLMDefaultRole`            | Role assigned to automatically created AnythingLLM users.                                                            | No          | `default`                   | Sent to `/api/v1/admin/users/new`                                                                                                                                                                                                                                                                                     |
| `anythingLLMDefaultWorkspacesSlugs` | Workspace slugs that should always be assigned to authenticated users.                                               | No          | None                        | Applied to both new and pre-existing users without removing existing members                                                                                                                                                                                                                                          |
| `anythingLLMLogoutDetectionPath`    | Path the AnythingLLM frontend redirects to after its own logout (e.g. `/login?nt=1`).                                | No          | `/login`                    | When a request to this path arrives with a valid middleware session, the plugin assumes AnythingLLM invalidated the user. Empty disables the feature. If configured without a leading slash, the plugin adds it.                                                                                                     |
| `anythingLLMLogoutAction`           | What to do when an AnythingLLM-side logout is detected.                                                              | No          | `keycloak`                  | `keycloak` performs a full Keycloak logout (same as `logoutPath`); `silent` clears the middleware session and silently re-issues the AnythingLLM SSO token.                                                                                                                                                           |
| `callbackPath`                      | Path where Traefik receives the OIDC callback from Keycloak.                                                         | No          | `/sso/callback`             | If configured without a leading slash, the plugin adds it                                                                                                                                                                                                                                                             |
| `loginPath`                         | Path intercepted by the middleware to start the OIDC login flow.                                                     | No          | `/sso/login`                | Starts the same login flow used when the session cookie expires. When the user already has a valid session, redirects to the AnythingLLM root instead. If configured without a leading slash, the plugin adds it.                                                                                                    |
| `logoutPath`                        | Path intercepted by the middleware to clear the session cookie and redirect to Keycloak logout.                      | No          | `/sso/logout`               | If configured without a leading slash, the plugin adds it                                                                                                                                                                                                                                                             |
| `sessionCookieName`                 | Name of the signed session cookie created by the middleware.                                                         | No          | `_anythingllm_keycloak_sso` | The plugin also uses `<sessionCookieName>_state` during login; changing `keycloakUsernameClaim` invalidates existing sessions                                                                                                                                                                                         |
| `sessionCookieSecure`               | Marks the middleware cookies as `Secure`.                                                                            | No          | `true`                      | Applies to both session and state cookies                                                                                                                                                                                                                                                                             |
| `sessionSecret`                     | Secret used to sign middleware cookies.                                                                              | Conditional | None                        | Required if `sessionSecretEnv` is not set or resolves to an empty value                                                                                                                                                                                                                                               |
| `sessionSecretEnv`                  | Environment variable name that contains the session signing secret.                                                  | Conditional | None                        | Takes precedence over `sessionSecret` when both are present                                                                                                                                                                                                                                                           |
| `sessionTTLSeconds`                 | Lifetime of the signed session cookie in seconds.                                                                    | No          | `3600`                      | Values less than or equal to `0` are reset to `3600`                                                                                                                                                                                                                                                                  |
| `insecureSkipTLSVerify`             | Disables TLS certificate verification for outbound requests to Keycloak and AnythingLLM.                             | No          | `false`                     | Intended only for controlled environments                                                                                                                                                                                                                                                                             |
