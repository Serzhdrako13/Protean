package api

import (
	"net/http"
	"strings"

	"protean/internal/auth"
	"protean/internal/store"
)

// GET /api/auth-methods/enabled -- public, unauthenticated: the login
// screen needs to know which methods are on BEFORE anyone is logged in, to
// decide what to render (plain form / method selector / SSO button). Never
// returns anything secret.
func (s *Server) apiAuthMethodsEnabled(w http.ResponseWriter, r *http.Request) {
	internalSettings, err := s.store.GetInternalAuthSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ldapSettings, err := s.store.GetLDAPSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	oidcSettings, err := s.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, map[string]bool{
		"internal": internalSettings.Enabled,
		"ldap":     ldapSettings.Enabled,
		"oidc":     oidcSettings.Enabled,
	})
}

type apiInternalAuthSettings struct {
	Enabled bool `json:"enabled"`
}

// GET /api/auth-methods/internal
func (s *Server) apiInternalAuthGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetInternalAuthSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiInternalAuthSettings(t))
}

// PUT /api/auth-methods/internal
func (s *Server) apiInternalAuthUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiInternalAuthSettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := s.store.SetInternalAuthSettings(r.Context(), store.InternalAuthSettings(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "auth_methods.internal.update", "")
	writeOK(w, nil)
}

type apiLDAPSettingsReq struct {
	Enabled       bool   `json:"enabled"`
	URL           string `json:"url"`
	SkipTLSVerify bool   `json:"skip_tls_verify"`
	BindDN        string `json:"bind_dn"`
	// BindPassword: blank keeps the existing sealed value -- same
	// "blank = don't change" convention as server SSH key rotation.
	BindPassword string `json:"bind_password"`
	UserBaseDN   string `json:"user_base_dn"`
	UserFilter   string `json:"user_filter"`
	GroupBaseDN  string `json:"group_base_dn"`
}

type apiLDAPSettingsResp struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"`
	SkipTLSVerify   bool   `json:"skip_tls_verify"`
	BindDN          string `json:"bind_dn"`
	BindPasswordSet bool   `json:"bind_password_set"`
	UserBaseDN      string `json:"user_base_dn"`
	UserFilter      string `json:"user_filter"`
	GroupBaseDN     string `json:"group_base_dn"`
}

// GET /api/auth-methods/ldap -- never returns the bind password itself,
// only whether one is set (same convention as servers' host_key_set).
func (s *Server) apiLDAPSettingsGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetLDAPSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiLDAPSettingsResp{
		Enabled: t.Enabled, URL: t.URL, SkipTLSVerify: t.SkipTLSVerify, BindDN: t.BindDN,
		BindPasswordSet: len(t.EncBindPassword) > 0, UserBaseDN: t.UserBaseDN,
		UserFilter: t.UserFilter, GroupBaseDN: t.GroupBaseDN,
	})
}

// PUT /api/auth-methods/ldap
func (s *Server) apiLDAPSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiLDAPSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	existing, err := s.store.GetLDAPSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	encBindPassword := existing.EncBindPassword
	if bp := strings.TrimSpace(req.BindPassword); bp != "" {
		sealed, err := s.enc.Seal(bp)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, msgf(r, "encrypt bind password: %v", "не удалось зашифровать bind password: %v", err))
			return
		}
		encBindPassword = sealed
	}
	t := store.LDAPSettings{
		Enabled: req.Enabled, URL: strings.TrimSpace(req.URL), SkipTLSVerify: req.SkipTLSVerify,
		BindDN: strings.TrimSpace(req.BindDN), EncBindPassword: encBindPassword,
		UserBaseDN: strings.TrimSpace(req.UserBaseDN), UserFilter: strings.TrimSpace(req.UserFilter),
		GroupBaseDN: strings.TrimSpace(req.GroupBaseDN),
	}
	if err := s.store.SetLDAPSettings(r.Context(), t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "auth_methods.ldap.update", "")
	// A generic "settings changed" entry doesn't say WHICH field changed --
	// call this out on its own every time it's saved enabled, not just on
	// the false->true transition, so it can't quietly go unnoticed by
	// someone reading the log after the one save that turned it on.
	if t.SkipTLSVerify {
		s.audit(r.Context(), "auth_methods.ldap.insecure_tls_verify_enabled", "")
	}
	writeOK(w, nil)
}

// POST /api/auth-methods/ldap/test -- a lightweight connectivity check
// (service bind only, no user search) so an admin can verify settings
// before flipping "enabled" on.
func (s *Server) apiLDAPSettingsTest(w http.ResponseWriter, r *http.Request) {
	var req apiLDAPSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	bindPassword := strings.TrimSpace(req.BindPassword)
	if bindPassword == "" {
		existing, err := s.store.GetLDAPSettings(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(existing.EncBindPassword) > 0 {
			opened, err := s.enc.Open(existing.EncBindPassword)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			bindPassword = opened
		}
	}
	settings := store.LDAPSettings{
		URL: strings.TrimSpace(req.URL), SkipTLSVerify: req.SkipTLSVerify,
		BindDN: strings.TrimSpace(req.BindDN), UserBaseDN: strings.TrimSpace(req.UserBaseDN),
	}
	if err := auth.TestLDAPConnection(r.Context(), settings, bindPassword); err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "connection failed: %v", "не удалось подключиться: %v", err))
		return
	}
	writeOKMsg(w, msg(r, "connection successful", "подключение успешно"), nil)
}

type apiOIDCSettingsReq struct {
	Enabled   bool   `json:"enabled"`
	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
	// ClientSecret: blank keeps the existing sealed value.
	ClientSecret    string `json:"client_secret"`
	Scopes          string `json:"scopes"`
	UsernameClaim   string `json:"username_claim"`
	GroupsClaim     string `json:"groups_claim"`
	RedirectBaseURL string `json:"redirect_base_url"`
}

type apiOIDCSettingsResp struct {
	Enabled         bool   `json:"enabled"`
	IssuerURL       string `json:"issuer_url"`
	ClientID        string `json:"client_id"`
	ClientSecretSet bool   `json:"client_secret_set"`
	Scopes          string `json:"scopes"`
	UsernameClaim   string `json:"username_claim"`
	GroupsClaim     string `json:"groups_claim"`
	RedirectBaseURL string `json:"redirect_base_url"`
	// CallbackPath is surfaced so the admin knows exactly what to register
	// with their IdP: redirect_base_url + this path.
	CallbackPath string `json:"callback_path"`
}

// GET /api/auth-methods/oidc
func (s *Server) apiOIDCSettingsGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiOIDCSettingsResp{
		Enabled: t.Enabled, IssuerURL: t.IssuerURL, ClientID: t.ClientID,
		ClientSecretSet: len(t.EncClientSecret) > 0, Scopes: t.Scopes,
		UsernameClaim: t.UsernameClaim, GroupsClaim: t.GroupsClaim,
		RedirectBaseURL: t.RedirectBaseURL, CallbackPath: auth.OIDCCallbackPath,
	})
}

// PUT /api/auth-methods/oidc
func (s *Server) apiOIDCSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiOIDCSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	existing, err := s.store.GetOIDCSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	encClientSecret := existing.EncClientSecret
	if cs := strings.TrimSpace(req.ClientSecret); cs != "" {
		sealed, err := s.enc.Seal(cs)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, msgf(r, "encrypt client secret: %v", "не удалось зашифровать client secret: %v", err))
			return
		}
		encClientSecret = sealed
	}
	t := store.OIDCSettings{
		Enabled: req.Enabled, IssuerURL: strings.TrimSpace(req.IssuerURL), ClientID: strings.TrimSpace(req.ClientID),
		EncClientSecret: encClientSecret, Scopes: strings.TrimSpace(req.Scopes),
		UsernameClaim: strings.TrimSpace(req.UsernameClaim), GroupsClaim: strings.TrimSpace(req.GroupsClaim),
		RedirectBaseURL: strings.TrimRight(strings.TrimSpace(req.RedirectBaseURL), "/"),
	}
	if err := s.store.SetOIDCSettings(r.Context(), t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "auth_methods.oidc.update", "")
	writeOK(w, nil)
}

// POST /api/auth-methods/oidc/test -- checks that the issuer's discovery
// document is reachable, so an admin can verify issuer_url before flipping
// "enabled" on.
func (s *Server) apiOIDCSettingsTest(w http.ResponseWriter, r *http.Request) {
	var req apiOIDCSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if err := auth.TestOIDCDiscovery(r.Context(), strings.TrimSpace(req.IssuerURL)); err != nil {
		writeErr(w, http.StatusBadGateway, msgf(r, "discovery failed: %v", "не удалось выполнить discovery: %v", err))
		return
	}
	writeOKMsg(w, msg(r, "discovery successful", "discovery выполнен успешно"), nil)
}

type apiAuthGroupRule struct {
	Method     string `json:"method"`
	Role       string `json:"role"`
	GroupValue string `json:"group_value"`
}

// GET /api/auth-methods/groups?method=ldap|oidc
func (s *Server) apiAuthGroupRulesList(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("method")
	if method != "ldap" && method != "oidc" {
		writeErr(w, http.StatusBadRequest, msg(r, "method must be \"ldap\" or \"oidc\"", "method должен быть \"ldap\" или \"oidc\""))
		return
	}
	rows, err := s.store.ListAuthGroupRules(r.Context(), method)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiAuthGroupRule, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiAuthGroupRule(row))
	}
	writeOK(w, out)
}

// POST /api/auth-methods/groups
func (s *Server) apiAuthGroupRulesAdd(w http.ResponseWriter, r *http.Request) {
	var req apiAuthGroupRule
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.Method != "ldap" && req.Method != "oidc" {
		writeErr(w, http.StatusBadRequest, msg(r, "method must be \"ldap\" or \"oidc\"", "method должен быть \"ldap\" или \"oidc\""))
		return
	}
	if req.Role != "admin" && req.Role != "user" {
		writeErr(w, http.StatusBadRequest, msg(r, "role must be \"admin\" or \"user\"", "role должен быть \"admin\" или \"user\""))
		return
	}
	req.GroupValue = strings.TrimSpace(req.GroupValue)
	if req.GroupValue == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "group_value is required", "необходимо указать group_value"))
		return
	}
	if err := s.store.AddAuthGroupRule(r.Context(), store.AuthGroupRule(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "auth_methods.group_rule.add", req.Method+" "+req.Role+" "+req.GroupValue)
	writeOK(w, nil)
}

// DELETE /api/auth-methods/groups?method=..&role=..&group_value=..
func (s *Server) apiAuthGroupRulesDelete(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("method")
	role := r.URL.Query().Get("role")
	groupValue := r.URL.Query().Get("group_value")
	if groupValue == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "group_value is required", "необходимо указать group_value"))
		return
	}
	if err := s.store.DeleteAuthGroupRule(r.Context(), method, role, groupValue); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "auth_methods.group_rule.delete", method+" "+role+" "+groupValue)
	writeOK(w, nil)
}
