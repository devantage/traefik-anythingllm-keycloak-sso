package traefik_anythingllm_keycloak_sso

import (
	"bytes"
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
	AnythingLLMLogoutDetectionPath    string   `json:"anythingLLMLogoutDetectionPath,omitempty"`
	AnythingLLMLogoutAction           string   `json:"anythingLLMLogoutAction,omitempty"`
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
		KeycloakScopes:                 "openid profile email",
		KeycloakUsernameClaim:          "preferred_username",
		KeycloakEmailClaim:             "email",
		AnythingLLMCreateUsers:         true,
		AnythingLLMDefaultRole:         "default",
		AnythingLLMLogoutDetectionPath: "/login",
		AnythingLLMLogoutAction:        "keycloak",
		CallbackPath:                   "/sso/callback",
		LoginPath:                      "/sso/login",
		LogoutPath:                     "/sso/logout",
		SessionCookieName:              "_anythingllm_keycloak_sso",
		SessionCookieSecure:            true,
		SessionTTLSeconds:              3600,
	}
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	keycloakClientSecret := resolveValue(config.KeycloakClientSecretEnv, config.KeycloakClientSecret)

	apiKey := resolveValue(config.AnythingLLMApiKeyEnv, config.AnythingLLMApiKey)

	sessionSecret := resolveValue(config.SessionSecretEnv, config.SessionSecret)

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
		return nil, errors.New("anythingLLMApiKey is required")
	case sessionSecret == "":
		return nil, errors.New("sessionSecret is required")
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

	if config.AnythingLLMLogoutDetectionPath != "" && !strings.HasPrefix(config.AnythingLLMLogoutDetectionPath, "/") {
		config.AnythingLLMLogoutDetectionPath = "/" + config.AnythingLLMLogoutDetectionPath
	}

	switch config.AnythingLLMLogoutAction {
	case "", "keycloak":
		config.AnythingLLMLogoutAction = "keycloak"
	case "silent":
	default:
		return nil, fmt.Errorf("anythingLLMLogoutAction must be %q or %q", "keycloak", "silent")
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
	if isAnythingLLMAPIPath(req.URL.Path) {
		m.next.ServeHTTP(rw, req)

		return
	}

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
		if m.config.AnythingLLMLogoutDetectionPath != "" && req.URL.Path == m.config.AnythingLLMLogoutDetectionPath {
			m.handleAnythingLLMLogout(rw, req)

			return
		}

		m.next.ServeHTTP(rw, req)

		return
	}

	if !shouldStartLogin(req) {
		m.writeError(rw, http.StatusUnauthorized, "authentication required")

		return
	}

	m.startLogin(rw, req)
}

func (m *Middleware) handleAnythingLLMLogout(rw http.ResponseWriter, req *http.Request) {
	if m.config.AnythingLLMLogoutAction == "silent" {
		m.clearCookie(rw, m.config.SessionCookieName)
		m.clearCookie(rw, m.stateCookieName())
		m.startLogin(rw, req)

		return
	}

	m.handleLogout(rw, req)
}

func (m *Middleware) handleLogin(rw http.ResponseWriter, req *http.Request) {
	if _, ok := m.readSession(req); ok {
		http.Redirect(rw, req, m.anythingPublicURL(req, "/"), http.StatusFound)
		return
	}

	m.startLogin(rw, req)
}

func (m *Middleware) startLogin(rw http.ResponseWriter, req *http.Request) {
	nonce, err := randomToken(32)

	if err != nil {
		m.writeError(rw, http.StatusInternalServerError, "failed to create login state")
		return
	}

	state := StatePayload{
		Nonce:     nonce,
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
	query.Set("redirect_uri", m.anythingPublicURL(req, m.config.CallbackPath))
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

	tokenResponse, err := m.exchangeCode(req.Context(), code, m.anythingPublicURL(req, m.config.CallbackPath))

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	userInfo, err := m.fetchUserInfo(req.Context(), tokenResponse.AccessToken)

	if err != nil {
		m.writeError(rw, http.StatusBadGateway, err.Error())
		return
	}

	username := firstNonEmpty(
		claimString(userInfo, m.config.KeycloakUsernameClaim),
		claimString(userInfo, m.config.KeycloakEmailClaim),
		claimString(userInfo, "sub"),
	)

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

	http.Redirect(rw, req, m.anythingPublicURL(req, loginPath), http.StatusFound)
}

func (m *Middleware) handleLogout(rw http.ResponseWriter, req *http.Request) {
	m.clearCookie(rw, m.config.SessionCookieName)

	m.clearCookie(rw, m.stateCookieName())

	query := url.Values{}

	query.Set("client_id", m.config.KeycloakClientID)
	query.Set("post_logout_redirect_uri", m.anythingPublicURL(req, "/"))

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
		return nil, err
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var token KeycloakExchangeTokenResponse

	if err := m.doJSON(request, &token); err != nil {
		return nil, fmt.Errorf("keycloak token exchange: %w", err)
	}

	if token.AccessToken == "" {
		return nil, errors.New("keycloak token response missing access_token")
	}

	return &token, nil
}

func (m *Middleware) fetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, m.issuerEndpoint("/protocol/openid-connect/userinfo"), nil)

	if err != nil {
		return nil, err
	}

	request.Header.Set("Authorization", "Bearer "+accessToken)

	var body map[string]any

	if err := m.doJSON(request, &body); err != nil {
		return nil, fmt.Errorf("keycloak userinfo: %w", err)
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
		return 0, fmt.Errorf("generate password for %q: %w", username, err)
	}

	payload := map[string]string{
		"username": username,
		"password": password,
		"role":     m.config.AnythingLLMDefaultRole,
	}

	var body AnythingCreateUserResponse

	if err := m.callAnythingLLM(ctx, http.MethodPost, "/api/v1/admin/users/new", payload, &body); err != nil {
		return 0, fmt.Errorf("create AnythingLLM user %q: %w", username, err)
	}

	if body.User == nil {
		return 0, fmt.Errorf("create AnythingLLM user %q: %s", username, firstNonEmpty(body.Error, "no user returned"))
	}

	return body.User.ID, nil
}

func (m *Middleware) listAnythingLLMUsers(ctx context.Context) ([]AnythingLLMUser, error) {
	var body AnythingLLMListUsersResponse

	if err := m.callAnythingLLM(ctx, http.MethodGet, "/api/v1/users", nil, &body); err != nil {
		return nil, fmt.Errorf("list AnythingLLM users: %w", err)
	}

	return body.Users, nil
}

func (m *Middleware) listAnythingLLMWorkspaces(ctx context.Context) ([]AnythingLLMWorkspace, error) {
	var body AnythingLLMWorkspacesResponse

	if err := m.callAnythingLLM(ctx, http.MethodGet, "/api/v1/workspaces", nil, &body); err != nil {
		return nil, fmt.Errorf("list AnythingLLM workspaces: %w", err)
	}

	return body.Workspaces, nil
}

func (m *Middleware) listAnythingLLMWorkspaceUsers(ctx context.Context, workspaceID int) ([]AnythingLLMWorkspaceUser, error) {
	var body AnythingLLMWorkspaceUsersResponse

	path := fmt.Sprintf("/api/v1/admin/workspaces/%d/users", workspaceID)

	if err := m.callAnythingLLM(ctx, http.MethodGet, path, nil, &body); err != nil {
		return nil, fmt.Errorf("list workspace %d users: %w", workspaceID, err)
	}

	return body.Users, nil
}

func (m *Middleware) addUserToAnythingLLMWorkspace(ctx context.Context, workspaceSlug string, userID int) error {
	payload := map[string]any{"userIds": []int{userID}, "reset": false}

	var body AnythingLLMWorkspaceManageUsersResponse

	path := "/api/v1/admin/workspaces/" + url.PathEscape(workspaceSlug) + "/manage-users"

	if err := m.callAnythingLLM(ctx, http.MethodPost, path, payload, &body); err != nil {
		return fmt.Errorf("add user to workspace %q: %w", workspaceSlug, err)
	}

	if !body.Success {
		return fmt.Errorf("workspace %q rejected membership update: %s", workspaceSlug, firstNonEmpty(body.Error, "unknown error"))
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
	var body AnythingLLMIssueTokenResponse

	path := fmt.Sprintf("/api/v1/users/%d/issue-auth-token", userID)

	if err := m.callAnythingLLM(ctx, http.MethodGet, path, nil, &body); err != nil {
		return "", fmt.Errorf("issue AnythingLLM auth token: %w", err)
	}

	if body.LoginPath == "" {
		return "", errors.New("AnythingLLM auth token response missing loginPath")
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

func (m *Middleware) doJSON(req *http.Request, target any) error {
	response, err := m.client.Do(req)

	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 512))

		return fmt.Errorf("HTTP %s: %s", response.Status, strings.TrimSpace(string(body)))
	}

	if target == nil {
		return nil
	}

	return json.NewDecoder(response.Body).Decode(target)
}

func (m *Middleware) callAnythingLLM(ctx context.Context, method, path string, body, target any) error {
	var reader io.Reader

	if body != nil {
		raw, err := json.Marshal(body)

		if err != nil {
			return err
		}

		reader = bytes.NewReader(raw)
	}

	request, err := http.NewRequestWithContext(ctx, method, m.anythingURL(path), reader)

	if err != nil {
		return err
	}

	request.Header.Set("Authorization", "Bearer "+m.anythingLLMKey)

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	return m.doJSON(request, target)
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

func (m *Middleware) anythingPublicURL(req *http.Request, path string) string {
	scheme := "http"

	if proto := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); proto != "" {
		scheme = proto
	} else if req.TLS != nil {
		scheme = "https"
	}

	host := strings.TrimSpace(req.Header.Get("X-Forwarded-Host"))

	if host == "" {
		host = req.Host
	}

	return scheme + "://" + host + path
}

func (m *Middleware) writeError(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")

	rw.WriteHeader(status)

	_, _ = rw.Write([]byte(m.name + ": " + message))
}

func (m *Middleware) stateCookieName() string {
	return m.config.SessionCookieName + "_state"
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

func claimString(payload map[string]any, key string) string {
	value, ok := payload[key]

	if !ok {
		return ""
	}

	text, _ := value.(string)

	return strings.TrimSpace(text)
}

func resolveValue(envName, value string) string {
	if envName != "" {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
	}

	return strings.TrimSpace(value)
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

func isAnythingLLMAPIPath(path string) bool {
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

func workspaceHasUser(users []AnythingLLMWorkspaceUser, userID int) bool {
	for _, user := range users {
		if user.UserID == userID {
			return true
		}
	}

	return false
}
