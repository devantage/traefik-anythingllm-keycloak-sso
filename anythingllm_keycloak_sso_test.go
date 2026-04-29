package traefik_anythingllm_keycloak_sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWithRedirectTo(t *testing.T) {
	got := withRedirectTo("/sso/simple?token=abc", "/workspaces/demo")
	want := "/sso/simple?redirectTo=%2Fworkspaces%2Fdemo&token=abc"

	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestRedirectsToKeycloakWhenSessionIsMissing(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		KeycloakScopes:         "openid profile email",
		KeycloakUsernameClaim:  "preferred_username",
		KeycloakEmailClaim:     "email",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
		SessionSecret:          "session-secret",
		CallbackPath:           "/sso/callback",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Accept", "text/html")
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

func TestLoginRouteRedirectsToKeycloak(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		SessionSecret:          "session-secret",
		CallbackPath:           "/sso/callback",
		LoginPath:              "/sso/login",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/sso/login", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Accept", "*/*")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")

	if !strings.HasPrefix(location, "https://keycloak.example.com/realms/cognitio/protocol/openid-connect/auth?") {
		t.Fatalf("unexpected redirect location: %s", location)
	}

	if !strings.Contains(location, "redirect_uri=https%3A%2F%2Fllm.example.com%2Fsso%2Fcallback") {
		t.Fatalf("expected redirect_uri in keycloak URL, got %s", location)
	}

	middleware := handler.(*Middleware)

	var stateCookie *http.Cookie

	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == middleware.stateCookieName() {
			stateCookie = cookie
			break
		}
	}

	if stateCookie == nil {
		t.Fatalf("expected state cookie to be set")
	}

	stateRequest := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	stateRequest.AddCookie(stateCookie)

	var state StatePayload

	if !middleware.readSignedCookie(stateRequest, middleware.stateCookieName(), &state) {
		t.Fatalf("failed to decode state cookie")
	}

	if state.ReturnTo != "/sso/login" {
		t.Fatalf("expected returnTo to mirror the requested path, got %q", state.ReturnTo)
	}
}

func TestUnauthenticatedAssetRequestReturnsUnauthorizedInsteadOfRedirect(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		KeycloakScopes:         "openid profile email",
		KeycloakUsernameClaim:  "preferred_username",
		KeycloakEmailClaim:     "email",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
		SessionSecret:          "session-secret",
		CallbackPath:           "/sso/callback",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/manifest.json", nil)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("Accept", "*/*")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	if location := recorder.Header().Get("Location"); location != "" {
		t.Fatalf("expected no redirect location, got %s", location)
	}
}

func TestReadSessionAcceptsMatchingUsernameClaim(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		KeycloakUsernameClaim:  "email",
		KeycloakEmailClaim:     "email",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		SessionSecret:          "session-secret",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", handler)
	}

	cookieRecorder := httptest.NewRecorder()

	if err := middleware.writeSignedCookie(cookieRecorder, middleware.config.SessionCookieName, SessionPayload{
		Username:      "alice@example.com",
		UsernameClaim: "email",
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}, time.Hour); err != nil {
		t.Fatalf("failed to write session cookie: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	request.AddCookie(cookieRecorder.Result().Cookies()[0])

	session, ok := middleware.readSession(request)
	if !ok {
		t.Fatalf("expected session to be accepted")
	}

	if session.Username != "alice@example.com" {
		t.Fatalf("expected username to round-trip, got %q", session.Username)
	}
}

func TestReadSessionRejectsChangedUsernameClaim(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		KeycloakUsernameClaim:  "email",
		KeycloakEmailClaim:     "email",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		SessionSecret:          "session-secret",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", handler)
	}

	cookieRecorder := httptest.NewRecorder()

	if err := middleware.writeSignedCookie(cookieRecorder, middleware.config.SessionCookieName, SessionPayload{
		Username:      "alice",
		UsernameClaim: "preferred_username",
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}, time.Hour); err != nil {
		t.Fatalf("failed to write session cookie: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	request.AddCookie(cookieRecorder.Result().Cookies()[0])

	if _, ok := middleware.readSession(request); ok {
		t.Fatalf("expected session to be rejected after username claim change")
	}
}

func TestReadSessionRejectsLegacySessionWithoutUsernameClaim(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:       "anythingllm",
		KeycloakClientSecret:   "secret",
		KeycloakUsernameClaim:  "email",
		KeycloakEmailClaim:     "email",
		AnythingLLMBaseURL:     "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:      "api-key",
		SessionSecret:          "session-secret",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionTTLSeconds:      3600,
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", handler)
	}

	cookieRecorder := httptest.NewRecorder()

	if err := middleware.writeSignedCookie(cookieRecorder, middleware.config.SessionCookieName, struct {
		Username  string `json:"username"`
		ExpiresAt int64  `json:"expiresAt"`
	}{
		Username:  "alice",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, time.Hour); err != nil {
		t.Fatalf("failed to write legacy session cookie: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://llm.example.com/", nil)
	request.AddCookie(cookieRecorder.Result().Cookies()[0])

	if _, ok := middleware.readSession(request); ok {
		t.Fatalf("expected legacy session without usernameClaim to be rejected")
	}
}

func TestLogoutRedirectsToKeycloakLogout(t *testing.T) {
	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:    "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:     "anythingllm",
		KeycloakClientSecret: "secret",
		AnythingLLMBaseURL:   "http://anythingllm.cognitio.svc.cluster.local:3001",
		AnythingLLMApiKey:    "api-key",
		LogoutPath:           "/logout",
		SessionCookieName:    "_anythingllm_keycloak_sso",
		SessionCookieSecure:  true,
		SessionSecret:        "session-secret",
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

func TestSyncDefaultWorkspacesAddsMissingMembershipOnly(t *testing.T) {
	t.Helper()

	var manageUsersCalls []string

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/api/v1/workspaces":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"workspaces": []map[string]any{
					{"id": 10, "slug": "engineering", "name": "Engineering"},
					{"id": 20, "slug": "support", "name": "Support"},
				},
			})
		case "/api/v1/admin/workspaces/10/users":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"users": []map[string]any{
					{"userId": 7, "role": "default"},
				},
			})
		case "/api/v1/admin/workspaces/20/users":
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"users": []map[string]any{
					{"userId": 1, "role": "admin"},
				},
			})
		case "/api/v1/admin/workspaces/support/manage-users":
			defer req.Body.Close()

			var body struct {
				UserIDs []int `json:"userIds"`
				Reset   bool  `json:"reset"`
			}

			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode manage-users payload: %v", err)
			}

			if len(body.UserIDs) != 1 || body.UserIDs[0] != 7 {
				t.Fatalf("unexpected userIds payload: %+v", body.UserIDs)
			}

			if body.Reset {
				t.Fatalf("expected reset=false")
			}

			manageUsersCalls = append(manageUsersCalls, req.URL.Path)
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"success": true,
				"error":   nil,
			})
		default:
			t.Fatalf("unexpected request path: %s", req.URL.Path)
		}
	}))
	defer server.Close()

	handler, err := New(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		KeycloakIssuerURL:                 "https://keycloak.example.com/realms/cognitio",
		KeycloakClientID:                  "anythingllm",
		KeycloakClientSecret:              "secret",
		AnythingLLMBaseURL:                server.URL,
		AnythingLLMApiKey:                 "api-key",
		SessionSecret:                     "session-secret",
		AnythingLLMDefaultWorkspacesSlugs: []string{"engineering", "support", "support"},
	}, "anythingllm-keycloak-sso")
	if err != nil {
		t.Fatalf("unexpected error creating middleware: %v", err)
	}

	middleware, ok := handler.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", handler)
	}

	if err := middleware.syncDefaultWorkspaces(context.Background(), 7); err != nil {
		t.Fatalf("unexpected sync error: %v", err)
	}

	if len(manageUsersCalls) != 1 {
		t.Fatalf("expected one manage-users call, got %d", len(manageUsersCalls))
	}
}
