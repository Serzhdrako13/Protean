package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// InternalAuthSettings toggles local username/password login. See
// internal/auth/manager.go's Login for how the EMERGENCY_ADMIN_* env vars
// stay usable even while this is disabled.
type InternalAuthSettings struct {
	Enabled bool
}

func defaultInternalAuthSettings() InternalAuthSettings {
	return InternalAuthSettings{Enabled: true}
}

func (s *Store) GetInternalAuthSettings(ctx context.Context) (InternalAuthSettings, error) {
	t := defaultInternalAuthSettings()
	err := s.pool.QueryRow(ctx, `SELECT enabled FROM wgpanel.internal_auth_settings WHERE id = true`).Scan(&t.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	return t, err
}

func (s *Store) SetInternalAuthSettings(ctx context.Context, t InternalAuthSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.internal_auth_settings (id, enabled, updated_at)
		VALUES (true, $1, now())
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()
	`, t.Enabled)
	return err
}

// LDAPSettings configures directory-based login. EncBindPassword is sealed
// via auth.Encryptor, same custody model as other secrets at rest.
type LDAPSettings struct {
	Enabled         bool
	URL             string
	SkipTLSVerify   bool
	BindDN          string
	EncBindPassword []byte
	UserBaseDN      string
	UserFilter      string
	GroupBaseDN     string
}

func defaultLDAPSettings() LDAPSettings {
	return LDAPSettings{UserFilter: "(uid=%s)"}
}

func (s *Store) GetLDAPSettings(ctx context.Context) (LDAPSettings, error) {
	t := defaultLDAPSettings()
	err := s.pool.QueryRow(ctx, `
		SELECT enabled, url, skip_tls_verify, bind_dn, enc_bind_password, user_base_dn, user_filter, group_base_dn
		FROM wgpanel.ldap_settings WHERE id = true
	`).Scan(&t.Enabled, &t.URL, &t.SkipTLSVerify, &t.BindDN, &t.EncBindPassword, &t.UserBaseDN, &t.UserFilter, &t.GroupBaseDN)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	return t, err
}

func (s *Store) SetLDAPSettings(ctx context.Context, t LDAPSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.ldap_settings (
			id, enabled, url, skip_tls_verify, bind_dn, enc_bind_password, user_base_dn, user_filter, group_base_dn, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled, url = EXCLUDED.url, skip_tls_verify = EXCLUDED.skip_tls_verify,
			bind_dn = EXCLUDED.bind_dn, enc_bind_password = EXCLUDED.enc_bind_password,
			user_base_dn = EXCLUDED.user_base_dn, user_filter = EXCLUDED.user_filter,
			group_base_dn = EXCLUDED.group_base_dn, updated_at = now()
	`, t.Enabled, t.URL, t.SkipTLSVerify, t.BindDN, t.EncBindPassword, t.UserBaseDN, t.UserFilter, t.GroupBaseDN)
	return err
}

// OIDCSettings configures generic OpenID Connect login (Keycloak/Authentik/
// Azure AD/etc). EncClientSecret is sealed via auth.Encryptor.
type OIDCSettings struct {
	Enabled         bool
	IssuerURL       string
	ClientID        string
	EncClientSecret []byte
	Scopes          string
	UsernameClaim   string
	GroupsClaim     string
	RedirectBaseURL string
}

func defaultOIDCSettings() OIDCSettings {
	return OIDCSettings{
		Scopes:        "openid profile email groups",
		UsernameClaim: "preferred_username",
		GroupsClaim:   "groups",
	}
}

func (s *Store) GetOIDCSettings(ctx context.Context) (OIDCSettings, error) {
	t := defaultOIDCSettings()
	err := s.pool.QueryRow(ctx, `
		SELECT enabled, issuer_url, client_id, enc_client_secret, scopes, username_claim, groups_claim, redirect_base_url
		FROM wgpanel.oidc_settings WHERE id = true
	`).Scan(&t.Enabled, &t.IssuerURL, &t.ClientID, &t.EncClientSecret, &t.Scopes, &t.UsernameClaim, &t.GroupsClaim, &t.RedirectBaseURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	return t, err
}

func (s *Store) SetOIDCSettings(ctx context.Context, t OIDCSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.oidc_settings (
			id, enabled, issuer_url, client_id, enc_client_secret, scopes, username_claim, groups_claim, redirect_base_url, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled, issuer_url = EXCLUDED.issuer_url, client_id = EXCLUDED.client_id,
			enc_client_secret = EXCLUDED.enc_client_secret, scopes = EXCLUDED.scopes,
			username_claim = EXCLUDED.username_claim, groups_claim = EXCLUDED.groups_claim,
			redirect_base_url = EXCLUDED.redirect_base_url, updated_at = now()
	`, t.Enabled, t.IssuerURL, t.ClientID, t.EncClientSecret, t.Scopes, t.UsernameClaim, t.GroupsClaim, t.RedirectBaseURL)
	return err
}

// AuthGroupRule is one entry in the admin-managed group-to-role mapping,
// scoped per method ("ldap"|"oidc") and role ("admin"|"user"). See
// internal/auth/manager.go's resolveRole: no match in either role's list
// for a method denies the login outright.
type AuthGroupRule struct {
	Method     string
	Role       string
	GroupValue string
}

func (s *Store) ListAuthGroupRules(ctx context.Context, method string) ([]AuthGroupRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT method, role, group_value FROM wgpanel.auth_group_rules WHERE method = $1 ORDER BY role, group_value
	`, method)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthGroupRule
	for rows.Next() {
		var r AuthGroupRule
		if err := rows.Scan(&r.Method, &r.Role, &r.GroupValue); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddAuthGroupRule(ctx context.Context, r AuthGroupRule) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.auth_group_rules (method, role, group_value) VALUES ($1, $2, $3)
		ON CONFLICT (method, role, group_value) DO NOTHING
	`, r.Method, r.Role, r.GroupValue)
	return err
}

func (s *Store) DeleteAuthGroupRule(ctx context.Context, method, role, groupValue string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM wgpanel.auth_group_rules WHERE method = $1 AND role = $2 AND group_value = $3
	`, method, role, groupValue)
	return err
}
