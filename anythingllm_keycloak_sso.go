package traefik_anythingllm_keycloak_sso

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	KeycloakIssuerURL                 string   `json:"keycloakIssuerURL,omitempty"`
	KeycloakClientID                  string   `json:"keycloakClientId,omitempty"`
	KeycloakClientSecret              string   `json:"keycloakClientSecret,omitempty"`
	KeycloakClientSecretEnv           string   `json:"keycloakClientSecretEnv,omitempty"`
	KeycloakScopes                    string   `json:"keycloakScopes,omitempty"`
	KeycloakUsernameClaim             string   `json:"keycloakUsernameClaim,omitempty"`
	KeycloakEmailClaim                string   `json:"keycloakEmailClaim,omitempty"`
	AnythingLLMBaseURL                string   `json:"anythingLLMBaseURL,omitempty"`
	AnythingLLMApiKey                 string   `json:"anythingLLMApiKey,omitempty"`
	AnythingLLMApiKeyEnv              string   `json:"anythingLLMApiKeyEnv,omitempty"`
	AnythingLLMCreateUsers            bool     `json:"anythingLLMCreateUsers,omitempty"`
	AnythingLLMDefaultRole            string   `json:"anythingLLMDefaultRole,omitempty"`
	AnythingLLMDefaultWorkspacesSlugs []string `json:"anythingLLMDefaultWorkspacesSlugs,omitempty"`
	CallbackPath                      string   `json:"callbackPath,omitempty"`
	LoginPath                         string   `json:"loginPath,omitempty"`
	LogoutPath                        string   `json:"logoutPath,omitempty"`
	SessionCookieName                 string   `json:"sessionCookieName,omitempty"`
	SessionCookieSecure               bool     `json:"sessionCookieSecure,omitempty"`
	InsecureSkipTLSVerify             bool     `json:"insecureSkipTLSVerify,omitempty"`
	SessionSecret                     string   `json:"sessionSecret,omitempty"`
	SessionSecretEnv                  string   `json:"sessionSecretEnv,omitempty"`
	SessionTTLSeconds                 int      `json:"sessionTTLSeconds,omitempty"`
}

type Middleware struct {
	next                 http.Handler
	name                 string
	config               *Config
	client               *http.Client
	keycloakClientSecret string
	anythingLLMKey       string
	sessionSecret        []byte
}

type StatePayload struct {
	Nonce     string `json:"nonce"`
	ReturnTo  string `json:"returnTo"`
	ExpiresAt int64  `json:"expiresAt"`
}

type SessionPayload struct {
	Username      string `json:"username"`
	UsernameClaim string `json:"usernameClaim"`
	ExpiresAt     int64  `json:"expiresAt"`
}

type KeycloakExchangeTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type AnythingLLMListUsersResponse struct {
	Users []AnythingLLMUser `json:"users"`
}

type AnythingLLMUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type AnythingLLMWorkspace struct {
	ID   int    `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type AnythingCreateUserResponse struct {
	User  *AnythingLLMUser `json:"user"`
	Error string           `json:"error"`
}

type AnythingLLMWorkspacesResponse struct {
	Workspaces []AnythingLLMWorkspace `json:"workspaces"`
}

type AnythingLLMIssueTokenResponse struct {
	Token     string `json:"token"`
	LoginPath string `json:"loginPath"`
}

type AnythingLLMWorkspaceUser struct {
	UserID int    `json:"userId"`
	Role   string `json:"role"`
}

type AnythingLLMWorkspaceUsersResponse struct {
	Users []AnythingLLMWorkspaceUser `json:"users"`
}

type AnythingLLMWorkspaceManageUsersResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

func CreateConfig() *Config {
	return &Config{
		KeycloakScopes:         "openid profile email",
		KeycloakUsernameClaim:  "preferred_username",
		KeycloakEmailClaim:     "email",
		AnythingLLMCreateUsers: true,
		AnythingLLMDefaultRole: "default",
		CallbackPath:           "/sso/callback",
		LoginPath:              "/sso/login",
		LogoutPath:             "/sso/logout",
		SessionCookieName:      "_anythingllm_keycloak_sso",
		SessionCookieSecure:    true,
		SessionTTLSeconds:      3600,
	}
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	keycloakClientSecret := firstNonEmpty(resolveEnv(config.KeycloakClientSecretEnv), config.KeycloakClientSecret)
	apiKey := firstNonEmpty(resolveEnv(config.AnythingLLMApiKeyEnv), config.AnythingLLMApiKey)
	sessionSecret := firstNonEmpty(resolveEnv(config.SessionSecretEnv), config.SessionSecret)

	switch {
	case strings.TrimSpace(config.KeycloakIssuerURL) == "":
		return nil, errors.New("keycloakIssuerURL is required")
	case strings.TrimSpace(config.KeycloakClientID) == "":
		return nil, errors.New("keycloakClientId is required")
	case keycloakClientSecret == "":
		return nil, errors.New("client secret is required")
	case strings.TrimSpace(config.AnythingLLMBaseURL) == "":
		return nil, errors.New("anythingLLMBaseURL is required")
	case apiKey == "":
		return nil, errors.New("AnythingLLM API key is required")
	case sessionSecret == "":
		return nil, errors.New("session secret is required")
	}

	if config.SessionTTLSeconds <= 0 {
		config.SessionTTLSeconds = 3600
	}

	if !strings.HasPrefix(config.CallbackPath, "/") {
		config.CallbackPath = "/" + config.CallbackPath
	}

	if config.LoginPath != "" && !strings.HasPrefix(config.LoginPath, "/") {
		config.LoginPath = "/" + config.LoginPath
	}

	if config.LogoutPath != "" && !strings.HasPrefix(config.LogoutPath, "/") {
		config.LogoutPath = "/" + config.LogoutPath
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if config.InsecureSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Middleware{
		next:                 next,
		name:                 name,
		config:               config,
		client:               &http.Client{Timeout: 15 * time.Second, Transport: transport},
		keycloakClientSecret: keycloakClientSecret,
		anythingLLMKey:       apiKey,
		sessionSecret:        []byte(sessionSecret),
	}, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
	case m.config.CallbackPath:
		m.handleCallback(rw, req)

		return
	case m.config.LoginPath:
		m.handleLogin(rw, req)

		return
	case m.config.LogoutPath:
		m.handleLogout(rw, req)

		return
	}

	if _, ok := m.readSession(req); ok {
		m.next.ServeHTTP(rw, req)

		return
	}

	if !shouldStartLogin(req) {
		m.writeError(rw, http.StatusUnauthorized, "authentication required")

		return
	}

	m.startLogin(rw, req, requestTarget(req))
}

func (m *Middleware) handleLogin(rw http.ResponseWriter, req *http.Request) {
	m.startLogin(rw, req, requestTarget(req))
}

func (m *Middleware) startLogin(rw http.ResponseWriter, req *http.Request, returnTo string) {
	nonce, err := randomToken(32)

	if err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to create login state")
		return
	}

	state := StatePayload{
		Nonce:     nonce,
		ReturnTo:  returnTo,
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	}

	if err := m.writeSignedCookie(rw, m.stateCookieName(), state, 10*time.Minute); err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to persist login state")
		return
	}

	query := url.Values{}

	query.Set("client_id", m.config.KeycloakClientID)
	query.Set("response_type", "code")
	query.Set("scope", m.config.KeycloakScopes)
	query.Set("redirect_uri", m.externalBaseURL(req)+m.config.CallbackPath)
	query.Set("state", nonce)

	http.Redirect(rw, req, m.issuerEndpoint("/protocol/openid-connect/auth")+"?"+query.Encode(), http.StatusFound)
}

func (m *Middleware) handleCallback(rw http.ResponseWriter, req *http.Request) {
	defer m.clearCookie(rw, m.stateCookieName())

	if errMessage := req.URL.Query().Get("error"); errMessage != "" {
		m.writeError(rw, http.StatusUnauthorized, "keycloak rejected authentication: "+errMessage)
		return
	}

	code := req.URL.Query().Get("code")

	stateToken := req.URL.Query().Get("state")

	if code == "" || stateToken == "" {
		m.writeError(rw, http.StatusBadRequest, "missing OIDC callback parameters")
		return
	}

	state, ok := m.readState(req)

	if !ok || state.Nonce != stateToken || state.ExpiresAt < time.Now().Unix() {
		m.writeError(rw, http.StatusUnauthorized, "invalid or expired login state")
		return
	}

	tokenResponse, err := m.exchangeCode(req.Context(), code, m.externalBaseURL(req)+m.config.CallbackPath)

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	userInfo, err := m.fetchUserInfo(req.Context(), tokenResponse.AccessToken)

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	username := claimString(userInfo, m.config.KeycloakUsernameClaim)

	email := claimString(userInfo, m.config.KeycloakEmailClaim)

	if username == "" {
		username = firstNonEmpty(email, claimString(userInfo, "sub"))
	}

	if username == "" {
		m.writeError(rw, http.StatusForbidden, "keycloak response did not include a usable username")
		return
	}

	userID, err := m.ensureAnythingLLMUser(req.Context(), username)

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	if err := m.syncDefaultWorkspaces(req.Context(), userID); err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	loginPath, err := m.issueAnythingLLMToken(req.Context(), userID)

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	if err := m.writeSignedCookie(rw, m.config.SessionCookieName, SessionPayload{
		Username:      username,
		UsernameClaim: m.sessionUsernameClaim(),
		ExpiresAt:     time.Now().Add(time.Duration(m.config.SessionTTLSeconds) * time.Second).Unix(),
	}, time.Duration(m.config.SessionTTLSeconds)*time.Second); err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to persist session")

		return
	}

	redirectURL := m.externalBaseURL(req) + withRedirectTo(loginPath, state.ReturnTo)

	http.Redirect(rw, req, redirectURL, http.StatusFound)
}

func (m *Middleware) handleLogout(rw http.ResponseWriter, req *http.Request) {
	m.clearCookie(rw, m.config.SessionCookieName)

	m.clearCookie(rw, m.stateCookieName())

	query := url.Values{}

	query.Set("client_id", m.config.KeycloakClientID)
	query.Set("post_logout_redirect_uri", m.externalBaseURL(req)+"/")

	http.Redirect(rw, req, m.issuerEndpoint("/protocol/openid-connect/logout")+"?"+query.Encode(), http.StatusFound)
}

func (m *Middleware) exchangeCode(ctx context.Context, code, redirectURI string) (*KeycloakExchangeTokenResponse, error) {
	form := url.Values{}

	form.Set("grant_type", "authorization_code")
	form.Set("client_id", m.config.KeycloakClientID)
	form.Set("client_secret", m.keycloakClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.issuerEndpoint("/protocol/openid-connect/token"), strings.NewReader(form.Encode()))

	if err != nil {
		return nil, fmt.Errorf("failed to prepare token request: %w", err)
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := m.client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("failed to exchange code with keycloak: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("keycloak token endpoint returned %s", response.Status)
	}

	var token KeycloakExchangeTokenResponse

	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode keycloak token response: %w", err)
	}

	if token.AccessToken == "" {
		return nil, errors.New("keycloak token response did not include an access token")
	}

	return &token, nil
}

func (m *Middleware) fetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.issuerEndpoint("/protocol/openid-connect/userinfo"), nil)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare userinfo request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := m.client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("failed to query keycloak userinfo endpoint: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("keycloak userinfo endpoint returned %s", response.Status)
	}

	var body map[string]any

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode keycloak userinfo response: %w", err)
	}

	return body, nil
}

func (m *Middleware) ensureAnythingLLMUser(ctx context.Context, username string) (int, error) {
	users, err := m.listAnythingLLMUsers(ctx)

	if err != nil {
		return 0, err
	}

	for _, user := range users {
		if strings.EqualFold(user.Username, username) {
			return user.ID, nil
		}
	}

	if !m.config.AnythingLLMCreateUsers {
		return 0, fmt.Errorf("AnythingLLM user %q does not exist and auto provisioning is disabled", username)
	}

	password, err := randomToken(24)

	if err != nil {
		return 0, fmt.Errorf("failed to generate bootstrap password for %q: %w", username, err)
	}

	payload, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"role":     m.config.AnythingLLMDefaultRole,
	})

	if err != nil {
		return 0, fmt.Errorf("failed to encode user creation payload: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.anythingURL("/api/v1/admin/users/new"), strings.NewReader(string(payload)))

	if err != nil {
		return 0, fmt.Errorf("failed to prepare AnythingLLM user creation request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)
	request.Header.Set("Content-Type", "application/json")

	response, err := m.client.Do(request)

	if err != nil {
		return 0, fmt.Errorf("failed to create AnythingLLM user %q: %w", username, err)
	}

	defer response.Body.Close()

	var body AnythingCreateUserResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("failed to decode AnythingLLM user creation response: %w", err)
	}

	if response.StatusCode >= 300 || body.User == nil {
		if body.Error == "" {
			body.Error = response.Status
		}

		return 0, fmt.Errorf("AnythingLLM rejected user creation for %q: %s", username, body.Error)
	}

	return body.User.ID, nil
}

func (m *Middleware) listAnythingLLMUsers(ctx context.Context) ([]AnythingLLMUser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.anythingURL("/api/v1/users"), nil)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare AnythingLLM users request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)

	response, err := m.client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("failed to list AnythingLLM users: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))

		return nil, fmt.Errorf("AnythingLLM users endpoint returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	var body AnythingLLMListUsersResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode AnythingLLM users response: %w", err)
	}

	return body.Users, nil
}

func (m *Middleware) listAnythingLLMWorkspaces(ctx context.Context) ([]AnythingLLMWorkspace, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.anythingURL("/api/v1/workspaces"), nil)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare AnythingLLM workspaces request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)

	response, err := m.client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("failed to list AnythingLLM workspaces: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))

		return nil, fmt.Errorf("AnythingLLM workspaces endpoint returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	var body AnythingLLMWorkspacesResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode AnythingLLM workspaces response: %w", err)
	}

	return body.Workspaces, nil
}

func (m *Middleware) listAnythingLLMWorkspaceUsers(ctx context.Context, workspaceID int) ([]AnythingLLMWorkspaceUser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.anythingURL(fmt.Sprintf("/api/v1/admin/workspaces/%d/users", workspaceID)), nil)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare AnythingLLM workspace users request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)

	response, err := m.client.Do(request)

	if err != nil {
		return nil, fmt.Errorf("failed to list AnythingLLM workspace users: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))

		return nil, fmt.Errorf("AnythingLLM workspace users endpoint returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	var body AnythingLLMWorkspaceUsersResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode AnythingLLM workspace users response: %w", err)
	}

	return body.Users, nil
}

func (m *Middleware) addUserToAnythingLLMWorkspace(ctx context.Context, workspaceSlug string, userID int) error {
	payload, err := json.Marshal(map[string]any{
		"userIds": []int{userID},
		"reset":   false,
	})

	if err != nil {
		return fmt.Errorf("failed to encode workspace membership payload for %q: %w", workspaceSlug, err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, m.anythingURL("/api/v1/admin/workspaces/"+url.PathEscape(workspaceSlug)+"/manage-users"), strings.NewReader(string(payload)))

	if err != nil {
		return fmt.Errorf("failed to prepare AnythingLLM workspace membership request for %q: %w", workspaceSlug, err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)
	request.Header.Set("Content-Type", "application/json")

	response, err := m.client.Do(request)

	if err != nil {
		return fmt.Errorf("failed to update AnythingLLM workspace membership for %q: %w", workspaceSlug, err)
	}

	defer response.Body.Close()

	var body AnythingLLMWorkspaceManageUsersResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return fmt.Errorf("failed to decode AnythingLLM workspace membership response for %q: %w", workspaceSlug, err)
	}

	if response.StatusCode >= 300 || !body.Success {
		if body.Error == "" {
			body.Error = response.Status
		}

		return fmt.Errorf("AnythingLLM rejected workspace membership update for %q: %s", workspaceSlug, body.Error)
	}

	return nil
}

func (m *Middleware) syncDefaultWorkspaces(ctx context.Context, userID int) error {
	targetSlugs := normalizedWorkspaceSlugs(m.config.AnythingLLMDefaultWorkspacesSlugs)

	if len(targetSlugs) == 0 {
		return nil
	}

	workspaces, err := m.listAnythingLLMWorkspaces(ctx)

	if err != nil {
		return err
	}

	workspaceBySlug := make(map[string]AnythingLLMWorkspace, len(workspaces))

	for _, workspace := range workspaces {
		workspaceBySlug[workspace.Slug] = workspace
	}

	for _, workspaceSlug := range targetSlugs {
		workspace, ok := workspaceBySlug[workspaceSlug]

		if !ok {
			return fmt.Errorf("AnythingLLM workspace %q was not found", workspaceSlug)
		}

		users, err := m.listAnythingLLMWorkspaceUsers(ctx, workspace.ID)

		if err != nil {
			return err
		}

		if workspaceHasUser(users, userID) {
			continue
		}

		if err := m.addUserToAnythingLLMWorkspace(ctx, workspace.Slug, userID); err != nil {
			return err
		}
	}

	return nil
}

func (m *Middleware) issueAnythingLLMToken(ctx context.Context, userID int) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.anythingURL(fmt.Sprintf("/api/v1/users/%d/issue-auth-token", userID)), nil)

	if err != nil {
		return "", fmt.Errorf("failed to prepare AnythingLLM auth token request: %w", err)
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)

	response, err := m.client.Do(request)

	if err != nil {
		return "", fmt.Errorf("failed to issue AnythingLLM auth token: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))

		return "", fmt.Errorf("AnythingLLM issue-auth-token returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	var body AnythingLLMIssueTokenResponse

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("failed to decode AnythingLLM auth token response: %w", err)
	}

	if body.LoginPath == "" {
		return "", errors.New("AnythingLLM auth token response did not include a loginPath")
	}

	return body.LoginPath, nil
}

func (m *Middleware) readSession(req *http.Request) (*SessionPayload, bool) {
	var payload SessionPayload

	if !m.readSignedCookie(req, m.config.SessionCookieName, &payload) {
		return nil, false
	}

	if payload.UsernameClaim != m.sessionUsernameClaim() {
		return nil, false
	}

	if payload.ExpiresAt < time.Now().Unix() {
		return nil, false
	}

	return &payload, true
}

func (m *Middleware) sessionUsernameClaim() string {
	return strings.TrimSpace(m.config.KeycloakUsernameClaim)
}

func (m *Middleware) readState(req *http.Request) (*StatePayload, bool) {
	var payload StatePayload

	if !m.readSignedCookie(req, m.stateCookieName(), &payload) {
		return nil, false
	}

	return &payload, true
}

func (m *Middleware) writeSignedCookie(rw http.ResponseWriter, name string, payload any, ttl time.Duration) error {
	raw, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(raw)

	signature := m.sign(raw)

	value := encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)

	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   m.config.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

func (m *Middleware) readSignedCookie(req *http.Request, name string, target any) bool {
	cookie, err := req.Cookie(name)

	if err != nil {
		return false
	}

	parts := strings.Split(cookie.Value, ".")

	if len(parts) != 2 {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])

	if err != nil {
		return false
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[1])

	if err != nil {
		return false
	}

	if !hmac.Equal(signature, m.sign(payload)) {
		return false
	}

	return json.Unmarshal(payload, target) == nil
}

func (m *Middleware) clearCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   m.config.SessionCookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (m *Middleware) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, m.sessionSecret)

	mac.Write(payload)

	return mac.Sum(nil)
}

func (m *Middleware) issuerEndpoint(path string) string {
	return strings.TrimRight(m.config.KeycloakIssuerURL, "/") + path
}

func (m *Middleware) anythingURL(path string) string {
	return strings.TrimRight(m.config.AnythingLLMBaseURL, "/") + path
}

func (m *Middleware) externalBaseURL(req *http.Request) string {
	scheme := req.Header.Get("X-Forwarded-Proto")

	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	host := req.Header.Get("X-Forwarded-Host")

	if host == "" {
		host = req.Host
	}

	return scheme + "://" + host
}

func (m *Middleware) writeError(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")

	rw.WriteHeader(status)

	_, _ = rw.Write([]byte(m.name + ": " + message))
}

func (m *Middleware) stateCookieName() string {
	return m.config.SessionCookieName + "_state"
}

func requestTarget(req *http.Request) string {
	target := req.URL.RequestURI()

	if target == "" {
		return "/"
	}

	return target
}

func shouldStartLogin(req *http.Request) bool {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}

	if strings.EqualFold(req.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return true
	}

	accept := strings.ToLower(req.Header.Get("Accept"))

	if strings.Contains(accept, "text/plain") || strings.Contains(accept, "text/html") || strings.Contains(accept, "application/javascript") || strings.Contains(accept, "text/css") {
		return true
	}

	return accept == "" && req.URL.Path == "/"
}

func withRedirectTo(loginPath, returnTo string) string {
	if returnTo == "" || returnTo == "/" {
		return loginPath
	}

	parsed, err := url.Parse(loginPath)

	if err != nil {
		return loginPath
	}

	query := parsed.Query()

	query.Set("redirectTo", returnTo)

	parsed.RawQuery = query.Encode()

	return parsed.String()
}

func claimString(payload map[string]any, key string) string {
	value, ok := payload[key]

	if !ok {
		return ""
	}

	text, _ := value.(string)

	return strings.TrimSpace(text)
}

func resolveEnv(name string) string {
	if name == "" {
		return ""
	}

	return strings.TrimSpace(os.Getenv(name))
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)

	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)

		if value != "" {
			return value
		}
	}

	return ""
}

func normalizedWorkspaceSlugs(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	slugs := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)

		if value == "" {
			continue
		}

		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		slugs = append(slugs, value)
	}

	return slugs
}

func workspaceHasUser(users []AnythingLLMWorkspaceUser, userID int) bool {
	for _, user := range users {
		if user.UserID == userID {
			return true
		}
	}

	return false
}
