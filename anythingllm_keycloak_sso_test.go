package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithRedirectTo(t *testing.T) {
	got := withRedirectTo("/sso/simple?token=abc", "/workspaces/demo")
	want := "/sso/simple?redirectTo=%2Fworkspaces%2Fdemo&token=abc"

	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestRedirectsToKeycloakWhenSessionIsMissing(t *testing.T) {
	handler, err := New(nil, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:       "https://keycloak.example.com/realms/cognitio",
		KaycloakClientID:        "anythingllm",
		KeycloakClientSecret:    "secret",
		KeycloakScopes:          "openid profile email",
		KeycloakUsernameClaim:   "preferred_username",
		KeycloakEmailClaim:      "email",
		AnythingLLMBaseURL:      "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:       "api-key",
		AnythingLLMCreateUsers:  true,
		AnythingLLMDefaultRole:  "default",
		SessionSecret:           "session-secret",
		CallbackPath:            "/_auth/keycloak/callback",
		SessionCookieName:       "_anythingllm_keycloak_sso",
		SessionTTLSeconds:       3600,

	}, "anythingllm-keycloak-sso")

	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")

	if !strings.HasPrefix(location, "https://keycloak.example.com/realms/cognitio/protocol/openid-connect/auth?") {
		t.Fatalf("unexpected redirect location: %s", location)
	}

	cookies := recorder.Result().Cookies()

	if len(cookies) == 0 || cookies[0].Name != "_anythingllm_keycloak_sso_state" {
		t.Fatalf("expected state cookie to be set, got %+v", cookies)
	}
}

func TestLogoutRedirectsToKeycloakLogout(t *testing.T) {
	handler, err := New(nil, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:     "https://keycloak.example.com/realms/cognitio",
		KaycloakClientID:      "anythingllm",
		KeycloakClientSecret:  "secret",
		AnythingLLMBaseURL:    "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:     "api-key",
		LogoutPath:            "/logout",
		SessionCookieName:     "_anythingllm_keycloak_sso",
		SessionCookieSecure:   true,
		SessionSecret:         "session-secret",
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/logout", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")

	if !strings.HasPrefix(location, "https://keycloak.example.com/realms/cognitio/protocol/openid-connect/logout?") {
		t.Fatalf("unexpected redirect location: %s", location)
	}

	if !strings.Contains(location, "client_id=anythingllm") {
		t.Fatalf("expected client_id in redirect location, got %s", location)
	}

	if !strings.Contains(location, "post_logout_redirect_uri=https%3A%2F%2Fllm.example.com%2F") {
		t.Fatalf("expected post_logout_redirect_uri in redirect location, got %s", location)
	}
}