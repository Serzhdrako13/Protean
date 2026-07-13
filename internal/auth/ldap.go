package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"protean/internal/store"
)

// ldapAuthenticate binds as the configured service account, finds the
// user's entry, then re-binds AS that entry with the supplied password --
// the re-bind succeeding or failing IS the credential check, no password
// is ever compared locally. Groups are read from the user entry's
// memberOf attribute (AD-style) if present; otherwise it falls back to
// searching group_base_dn for both groupOfNames ("member") and posixGroup
// ("memberUid") style membership, since generic LDAP servers vary.
// bindPassword must already be decrypted -- this function has no notion of
// the encryption scheme, that's the caller's (Manager's) concern.
func ldapAuthenticate(ctx context.Context, settings store.LDAPSettings, bindPassword, username, password string) ([]string, error) {
	if settings.URL == "" {
		return nil, fmt.Errorf("ldap: server url not configured")
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second})}
	if settings.SkipTLSVerify {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	conn, err := ldap.DialURL(settings.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)

	if settings.BindDN != "" {
		if err := conn.Bind(settings.BindDN, bindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service bind: %w", err)
		}
	}

	filter := fmt.Sprintf(settings.UserFilter, ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		settings.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{"dn", "memberOf"}, nil,
	)
	res, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: user search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("ldap: user not found or ambiguous")
	}
	entry := res.Entries[0]

	// Separate connection for the credential check so the service-bound
	// conn above stays usable for the group-search fallback below.
	userConn, err := ldap.DialURL(settings.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	defer userConn.Close()
	userConn.SetTimeout(10 * time.Second)
	if err := userConn.Bind(entry.DN, password); err != nil {
		return nil, fmt.Errorf("ldap: invalid credentials: %w", err)
	}

	groups := entry.GetAttributeValues("memberOf")
	if len(groups) == 0 && settings.GroupBaseDN != "" {
		groupFilter := fmt.Sprintf("(|(member=%s)(memberUid=%s))", ldap.EscapeFilter(entry.DN), ldap.EscapeFilter(username))
		groupReq := ldap.NewSearchRequest(
			settings.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
			groupFilter, []string{"dn"}, nil,
		)
		if groupRes, err := conn.Search(groupReq); err == nil {
			for _, g := range groupRes.Entries {
				groups = append(groups, g.DN)
			}
		}
	}
	return groups, nil
}

// TestLDAPConnection is a lightweight connectivity check for the settings
// UI: dial + (if configured) service bind, no user search -- lets an admin
// verify host/bind-DN/bind-password before flipping "enabled" on.
func TestLDAPConnection(ctx context.Context, settings store.LDAPSettings, bindPassword string) error {
	if settings.URL == "" {
		return fmt.Errorf("ldap: server url not configured")
	}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second})}
	if settings.SkipTLSVerify {
		opts = append(opts, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	conn, err := ldap.DialURL(settings.URL, opts...)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(10 * time.Second)
	if settings.BindDN != "" {
		if err := conn.Bind(settings.BindDN, bindPassword); err != nil {
			return fmt.Errorf("service bind: %w", err)
		}
	}
	return nil
}

// LoginLDAP authenticates against the configured LDAP/AD server and, on
// success, resolves the account's role via the shared external-login tail
// (Manager.FinishExternalLogin) -- see ldapAuthenticate for how the bind
// itself works.
func (m *Manager) LoginLDAP(ctx context.Context, username, password string) (token string, expiresAt time.Time, err error) {
	settings, err := m.store.GetLDAPSettings(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("load ldap settings: %w", err)
	}
	if !settings.Enabled {
		return "", time.Time{}, ErrMethodDisabled
	}
	bindPassword, err := m.enc.Open(settings.EncBindPassword)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("decrypt ldap bind password: %w", err)
	}
	groups, err := ldapAuthenticate(ctx, settings, bindPassword, username, password)
	if err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	return m.FinishExternalLogin(ctx, "ldap", username, groups)
}
