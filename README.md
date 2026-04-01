# Traefik AnythingLLM Keycloak SSO

Traefik middleware plugin that authenticates AnythingLLM users via OIDC with Keycloak.

## Flow

1. Redirects the user to Keycloak.
2. Receives the OIDC callback in Traefik.
3. Calls `userinfo` to identify the authenticated user.
4. Looks up or creates the user in AnythingLLM.
5. Issues a temporary token via `/api/v1/users/{id}/issue-auth-token`.
6. Redirects the browser to `/sso/simple?token=...`.

## Requirements

- Keycloak with an OIDC client configured for the Traefik callback.
- AnythingLLM in multi-user mode`.
- AnythingLLM onboarding completed.
- AnythingLLM environment variable set as `SIMPLE_SSO_ENABLED=1`.
- AnythingLLM API key with permission to list users, create users, and issue temporary tokens.

## Installation

```yaml
experimental:
  plugins:
    anythingllmKeycloakSso:
      moduleName: github.com/devantage/traefik-anythingllm-keycloak-sso
      version: v0.1.0
```

## Usage

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: anythingllm-keycloak-sso
spec:
  plugin:
    anythingllmKeycloakSso:
      keycloakIssuerURL: https://keycloak.example.com/realms/example
      clientID: anythingllm
      clientSecretEnv: TRAEFIK_KEYCLOAK_CLIENT_SECRET
      anythingLLMBaseURL: http://anythingllm.default.svc.cluster.local:3001
      anythingLLMApiKeyEnv: TRAEFIK_ANYTHINGLLM_API_KEY
      sessionSecretEnv: TRAEFIK_ANYTHINGLLM_SSO_SESSION_SECRET
      callbackPath: /_auth/keycloak/callback
      logoutPath: /logout
      sessionCookieName: _anythingllm_keycloak_sso
      sessionTTLSeconds: 3600
      scopes: openid profile email
      usernameClaim: preferred_username
      emailClaim: email
      defaultRole: default
      createUsers: true
      cookieSecure: true
```

## Configuration Parameters

| Name                    | Description                                                                                           | Required    | Default                     | Notes                                              |
| ----------------------- | ----------------------------------------------------------------------------------------------------- | ----------- | --------------------------- | -------------------------------------------------- |
| `keycloakIssuerURL`     | Base issuer URL for the Keycloak realm used for OIDC discovery and endpoints.                         | Yes         | None                        |                                                    |
| `clientID`              | OIDC client ID registered in Keycloak.                                                                | Yes         | None                        |                                                    |
| `clientSecret`          | OIDC client secret provided directly in the middleware configuration.                                 | Conditional | None                        | Required if `clientSecretEnv` is not defined.      |
| `clientSecretEnv`       | Environment variable name that contains the OIDC client secret.                                       | Conditional | None                        | Required if `clientSecret` is not defined.         |
| `anythingLLMBaseURL`    | Base URL of the AnythingLLM instance.                                                                 | Yes         | None                        |                                                    |
| `anythingLLMApiKey`     | AnythingLLM API key provided directly in the middleware configuration.                                | Conditional | None                        | Required if `anythingLLMApiKeyEnv` is not defined. |
| `anythingLLMApiKeyEnv`  | Environment variable name that contains the AnythingLLM API key.                                      | Conditional | None                        | Required if `anythingLLMApiKey` is not defined.    |
| `sessionSecret`         | Secret used to sign middleware cookies, provided directly in the configuration.                       | Conditional | None                        | Required if `sessionSecretEnv` is not defined.     |
| `sessionSecretEnv`      | Environment variable name that contains the session signing secret.                                   | Conditional | None                        | Required if `sessionSecret` is not defined.        |
| `callbackPath`          | Path where Traefik receives the OIDC callback from Keycloak.                                          | No          | `/_auth/keycloak/callback`  |                                                    |
| `logoutPath`            | Path intercepted by the middleware to clear the SSO session cookie.                                   | No          | `/logout`                   |                                                    |
| `sessionCookieName`     | Name of the session cookie created by the middleware.                                                 | No          | `_anythingllm_keycloak_sso` |                                                    |
| `sessionTTLSeconds`     | Lifetime of the session cookie in seconds. Values less than or equal to `0` are reset to the default. | No          | `3600`                      |                                                    |
| `scopes`                | OAuth scopes requested during login.                                                                  | No          | `openid profile email`      |                                                    |
| `usernameClaim`         | Claim used to extract the username from Keycloak `userinfo`.                                          | No          | `preferred_username`        |                                                    |
| `emailClaim`            | Claim used to extract the email from Keycloak `userinfo`.                                             | No          | `email`                     |                                                    |
| `defaultRole`           | Role assigned when automatically creating a new AnythingLLM user.                                     | No          | `default`                   |                                                    |
| `createUsers`           | Enables automatic user provisioning in AnythingLLM when the user does not already exist.              | No          | `true`                      |                                                    |
| `cookieSecure`          | Marks the session cookie as `Secure`.                                                                 | No          | `true`                      |                                                    |
| `insecureSkipTLSVerify` | Disables TLS certificate verification for outbound requests to Keycloak and AnythingLLM.              | No          | `false`                     |                                                    |
