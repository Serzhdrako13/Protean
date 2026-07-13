package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"protean/internal/store"
)

// OIDCCallbackPath is appended to redirect_base_url to build the
// redirect_uri registered with the IdP -- kept as a constant so the admin
// UI's copy-paste-into-your-IdP instructions and the actual route
// registration (internal/api/server.go) can never drift apart.
const OIDCCallbackPath = "/api/auth/oidc/callback"

func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildOIDCConfig(provider *oidc.Provider, settings store.OIDCSettings, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     settings.ClientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(settings.RedirectBaseURL, "/") + OIDCCallbackPath,
		Scopes:       strings.Fields(settings.Scopes),
	}
}

// TestOIDCDiscovery is a lightweight check for the settings UI: confirms
// the issuer's discovery document is reachable, before flipping "enabled"
// on. Doesn't exercise the full auth-code flow (that needs a real browser
// redirect through the IdP).
func TestOIDCDiscovery(ctx context.Context, issuerURL string) error {
	if issuerURL == "" {
		return fmt.Errorf("issuer_url not configured")
	}
	_, err := oidc.NewProvider(ctx, issuerURL)
	return err
}

// StartOIDC builds the authorization-code+PKCE redirect URL for the
// configured IdP -- clientSecret must already be decrypted (see
// LoginLDAP's bindPassword for the same convention).
func (m *Manager) StartOIDC(ctx context.Context) (authURL string, err error) {
	settings, err := m.store.GetOIDCSettings(ctx)
	if err != nil {
		return "", fmt.Errorf("load oidc settings: %w", err)
	}
	if !settings.Enabled {
		return "", ErrMethodDisabled
	}
	if settings.IssuerURL == "" || settings.RedirectBaseURL == "" {
		return "", fmt.Errorf("oidc: issuer_url/redirect_base_url not configured")
	}
	clientSecret, err := m.enc.Open(settings.EncClientSecret)
	if err != nil {
		return "", fmt.Errorf("decrypt oidc client secret: %w", err)
	}
	provider, err := oidc.NewProvider(ctx, settings.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	conf := buildOIDCConfig(provider, settings, clientSecret)

	verifier := oauth2.GenerateVerifier()
	nonce, err := randomNonce()
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	state := m.oidcState.Issue(verifier, nonce)
	return conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

// FinishOIDC completes the callback: verifies the signed state, exchanges
// the code, verifies the ID token (nonce/issuer/audience), and extracts
// (username, groups) using the configured claim names -- falling back to
// the userinfo endpoint if the groups claim isn't present on the ID token,
// since several IdPs only expose it there. On success it hands off to the
// shared external-login tail, exactly like LoginLDAP.
func (m *Manager) FinishOIDC(ctx context.Context, state, code string) (token string, expiresAt time.Time, err error) {
	settings, err := m.store.GetOIDCSettings(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("load oidc settings: %w", err)
	}
	if !settings.Enabled {
		return "", time.Time{}, ErrMethodDisabled
	}
	username, groups, err := m.exchangeOIDC(ctx, settings, state, code)
	if err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	return m.FinishExternalLogin(ctx, "oidc", username, groups)
}

func (m *Manager) exchangeOIDC(ctx context.Context, settings store.OIDCSettings, state, code string) (username string, groups []string, err error) {
	verifier, nonce, ok := m.oidcState.Verify(state)
	if !ok {
		return "", nil, fmt.Errorf("oidc: invalid or expired state")
	}
	clientSecret, err := m.enc.Open(settings.EncClientSecret)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt oidc client secret: %w", err)
	}
	provider, err := oidc.NewProvider(ctx, settings.IssuerURL)
	if err != nil {
		return "", nil, fmt.Errorf("oidc discovery: %w", err)
	}
	conf := buildOIDCConfig(provider, settings, clientSecret)

	oauthToken, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", nil, fmt.Errorf("oidc: exchange: %w", err)
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		return "", nil, fmt.Errorf("oidc: no id_token in token response")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: settings.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return "", nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return "", nil, fmt.Errorf("oidc: nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return "", nil, fmt.Errorf("oidc: decode claims: %w", err)
	}
	username, _ = claims[settings.UsernameClaim].(string)
	if username == "" {
		return "", nil, fmt.Errorf("oidc: username claim %q missing from id_token", settings.UsernameClaim)
	}

	groups = extractGroupsClaim(claims, settings.GroupsClaim)
	if len(groups) == 0 {
		if userInfo, uerr := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauthToken)); uerr == nil {
			var uiClaims map[string]any
			if uerr := userInfo.Claims(&uiClaims); uerr == nil {
				groups = extractGroupsClaim(uiClaims, settings.GroupsClaim)
			}
		}
	}
	return username, groups, nil
}

func extractGroupsClaim(claims map[string]any, claimName string) []string {
	raw, ok := claims[claimName]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
