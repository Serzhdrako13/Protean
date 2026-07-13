// Package auth handles panel login: password hashing, session tokens
// backed by Postgres, and login rate limiting. It's deliberately
// transport-agnostic -- cookie handling lives in internal/api.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"protean/internal/store"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrAccountDisabled/ErrPortalAccessDenied are returned by Login/
// CompleteTOTPLogin instead of ErrInvalidCredentials once the password (and
// TOTP code, where relevant) already checked out -- distinct messages are
// safe to surface to the user at that point (no enumeration risk: they've
// already proven they know the password).
var ErrAccountDisabled = errors.New("account disabled")
var ErrPortalAccessDenied = errors.New("portal access denied")

// ErrInternalAuthDisabled is returned by Login when the admin has turned
// off local username/password login (see internal_auth_settings) and the
// submitted username isn't the configured break-glass emergency admin.
var ErrInternalAuthDisabled = errors.New("internal authentication is disabled")

// ErrMethodDisabled is returned by the LDAP/OIDC login paths when that
// method is currently toggled off.
var ErrMethodDisabled = errors.New("this login method is disabled")

// ErrNoGroupMatch is returned by external logins when the authenticated
// account's groups match neither role's configured list -- per design,
// this denies the login outright rather than falling back to a default
// role.
var ErrNoGroupMatch = errors.New("account is not a member of any allowed group")

// DefaultSessionTTL is used only if the password_policy_settings row can't
// be read (e.g. store error) -- normally the configurable session_ttl_hours
// setting (see store.PasswordPolicySettings) governs session lifetime.
const DefaultSessionTTL = 30 * 24 * time.Hour

// dummyHash is a real bcrypt hash (of an unguessable, unused password) computed
// once at startup so a lookup for a nonexistent username still pays bcrypt's
// full cost -- otherwise the login endpoint would respond faster for unknown
// usernames than for wrong passwords, leaking which usernames exist.
var dummyHash = mustHashPassword("wgpanel-timing-safety-placeholder")

func mustHashPassword(password string) string {
	hash, err := HashPassword(password)
	if err != nil {
		panic(fmt.Sprintf("hash placeholder password: %v", err))
	}
	return hash
}

type Manager struct {
	store  *store.Store
	hasher tokenHasher
	enc    *Encryptor
	// emergencyUsername, if non-empty, is the break-glass local admin
	// (EMERGENCY_ADMIN_USERNAME/EMERGENCY_ADMIN_PASSWORD) that keeps
	// working via local password even while internal_auth_settings.enabled
	// is false -- see Login/Authenticate.
	emergencyUsername string
	oidcState         *OIDCState
}

func NewManager(s *store.Store, sessionSecret string, enc *Encryptor, emergencyUsername string) *Manager {
	return &Manager{
		store: s, hasher: newTokenHasher(sessionSecret), enc: enc,
		emergencyUsername: emergencyUsername, oidcState: NewOIDCState(sessionSecret),
	}
}

// SeedEmergencyAdmin force-creates (or resets) the break-glass admin
// account every startup while EMERGENCY_ADMIN_USERNAME/PASSWORD are set --
// unlike SeedAdmin (only fires when the table is empty), this always
// applies, so it works as a genuine escape hatch even when other admins
// already exist. Role and enabled are force-set too, in case a
// pre-existing local account of the same username had drifted away from
// admin/enabled. The caller (cmd/panel/main.go) is expected to log loudly
// whenever this runs.
func (m *Manager) SeedEmergencyAdmin(ctx context.Context, username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	existing, err := m.store.GetUserByUsernameAndSource(ctx, username, "local")
	if errors.Is(err, store.ErrNotFound) {
		_, err := m.store.CreateUser(ctx, username, hash, "admin")
		return err
	}
	if err != nil {
		return fmt.Errorf("look up emergency admin: %w", err)
	}
	if err := m.store.UpdateUserPassword(ctx, existing.ID, hash); err != nil {
		return err
	}
	if err := m.store.UpdateUserRole(ctx, existing.ID, "admin"); err != nil {
		return err
	}
	return m.store.UpdateUserEnabled(ctx, existing.ID, true)
}

// SeedAdmin creates the initial admin user if the users table is empty.
// Safe to call on every startup.
func (m *Manager) SeedAdmin(ctx context.Context, username, password string) error {
	count, err := m.store.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return nil
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = m.store.CreateUser(ctx, username, hash, "admin")
	return err
}

// CreateUser creates a new account with the given role ("admin" or "user") --
// used by the admin "Users" management page to provision portal accounts.
func (m *Manager) CreateUser(ctx context.Context, username, password, role string) error {
	policy, err := m.store.GetPasswordPolicySettings(ctx)
	if err != nil {
		return fmt.Errorf("load password policy: %w", err)
	}
	if err := ValidatePassword(policy, password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = m.store.CreateUser(ctx, username, hash, role)
	return err
}

// AdminSetPassword force-sets a user's password without checking the old
// one (an admin resetting another account) -- distinct from the
// self-service ChangePassword below, which requires the current password.
// Only ever targets local accounts (LDAP/OIDC accounts have no local
// password to set).
func (m *Manager) AdminSetPassword(ctx context.Context, username, newPassword string) error {
	policy, err := m.store.GetPasswordPolicySettings(ctx)
	if err != nil {
		return fmt.Errorf("load password policy: %w", err)
	}
	if err := ValidatePassword(policy, newPassword); err != nil {
		return err
	}
	user, err := m.store.GetUserByUsernameAndSource(ctx, username, "local")
	if err != nil {
		return fmt.Errorf("look up user: %w", err)
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return m.store.UpdateUserPassword(ctx, user.ID, hash)
}

// Login verifies the password. If the user has 2FA enabled, it returns
// needTOTP=true and NO session -- the caller must then call
// CompleteTOTPLogin with a valid code. Otherwise it creates and returns a
// session token immediately.
func (m *Manager) Login(ctx context.Context, username, password string) (token string, expiresAt time.Time, needTOTP bool, err error) {
	intSettings, err := m.store.GetInternalAuthSettings(ctx)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("load internal auth settings: %w", err)
	}
	isEmergency := m.emergencyUsername != "" && username == m.emergencyUsername
	if !intSettings.Enabled && !isEmergency {
		return "", time.Time{}, false, ErrInternalAuthDisabled
	}
	user, err := m.store.GetUserByUsernameAndSource(ctx, username, "local")
	if errors.Is(err, store.ErrNotFound) {
		// Still run bcrypt so username enumeration can't be timed.
		CheckPassword(dummyHash, password)
		return "", time.Time{}, false, ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("look up user: %w", err)
	}
	if !CheckPassword(user.PasswordHash, password) {
		return "", time.Time{}, false, ErrInvalidCredentials
	}
	if err := checkAccountLoginAllowed(user); err != nil {
		return "", time.Time{}, false, err
	}
	if user.TOTPEnabled {
		return "", time.Time{}, true, nil
	}
	token, expiresAt, err = m.createSession(ctx, user.ID)
	return token, expiresAt, false, err
}

// checkAccountLoginAllowed applies the enabled/portal-access gates once the
// password (and, from CompleteTOTPLogin, the TOTP code) has already been
// verified. portal_access_enabled only matters for role == "user" -- admin
// accounts never reach the portal, so it's never checked for them.
func checkAccountLoginAllowed(user store.User) error {
	if !user.Enabled {
		return ErrAccountDisabled
	}
	if user.Role == "user" && !user.PortalAccessEnabled {
		return ErrPortalAccessDenied
	}
	return nil
}

// CompleteTOTPLogin finishes a login that requires 2FA: it re-verifies that
// the user has 2FA enabled and that the code is valid, then issues a session.
func (m *Manager) CompleteTOTPLogin(ctx context.Context, username, code string) (token string, expiresAt time.Time, err error) {
	user, err := m.store.GetUserByUsernameAndSource(ctx, username, "local")
	if err != nil {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if !user.TOTPEnabled || !ValidateTOTP(user.TOTPSecret, code) {
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err := checkAccountLoginAllowed(user); err != nil {
		return "", time.Time{}, err
	}
	return m.createSession(ctx, user.ID)
}

func (m *Manager) createSession(ctx context.Context, userID int64) (string, time.Time, error) {
	raw, hash, err := m.hasher.generate()
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := DefaultSessionTTL
	if policy, err := m.store.GetPasswordPolicySettings(ctx); err == nil && policy.SessionTTLHours > 0 {
		ttl = time.Duration(policy.SessionTTLHours) * time.Hour
	}
	expiresAt := time.Now().Add(ttl)
	if err := m.store.CreateSession(ctx, userID, hash, expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("create session: %w", err)
	}
	return raw, expiresAt, nil
}

// Authenticate resolves a raw session token from a cookie into the
// logged-in user's ID, username, role, auth source, and the account's
// password_changed_at (for the password-expiry gate in
// internal/api/api_common.go's requireAuthAPI). A session whose owning
// login method (internal/ldap/oidc) has since been disabled is treated as
// invalid, same as an already-disabled account -- except the emergency
// admin, who is always exempt from the internal-disabled check.
func (m *Manager) Authenticate(ctx context.Context, rawToken string) (userID int64, username, role, authSource string, passwordChangedAt time.Time, err error) {
	sess, err := m.store.GetSession(ctx, m.hasher.hash(rawToken))
	if errors.Is(err, store.ErrNotFound) {
		return 0, "", "", "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return 0, "", "", "", time.Time{}, fmt.Errorf("look up session: %w", err)
	}
	if sess.AuthSource == "local" && !(m.emergencyUsername != "" && sess.Username == m.emergencyUsername) {
		intSettings, err := m.store.GetInternalAuthSettings(ctx)
		if err != nil {
			return 0, "", "", "", time.Time{}, fmt.Errorf("load internal auth settings: %w", err)
		}
		if !intSettings.Enabled {
			return 0, "", "", "", time.Time{}, ErrInvalidCredentials
		}
	} else if sess.AuthSource == "ldap" {
		ldapSettings, err := m.store.GetLDAPSettings(ctx)
		if err != nil {
			return 0, "", "", "", time.Time{}, fmt.Errorf("load ldap settings: %w", err)
		}
		if !ldapSettings.Enabled {
			return 0, "", "", "", time.Time{}, ErrInvalidCredentials
		}
	} else if sess.AuthSource == "oidc" {
		oidcSettings, err := m.store.GetOIDCSettings(ctx)
		if err != nil {
			return 0, "", "", "", time.Time{}, fmt.Errorf("load oidc settings: %w", err)
		}
		if !oidcSettings.Enabled {
			return 0, "", "", "", time.Time{}, ErrInvalidCredentials
		}
	}
	return sess.UserID, sess.Username, sess.Role, sess.AuthSource, sess.PasswordChangedAt, nil
}

func (m *Manager) Logout(ctx context.Context, rawToken string) error {
	return m.store.DeleteSession(ctx, m.hasher.hash(rawToken))
}

// ChangePassword verifies the current password and sets a new one. id is
// the session's user ID (not username -- a bare username no longer
// identifies a unique account). Only meaningful for auth_source=="local"
// accounts; LDAP/OIDC accounts have no PasswordHash to check against, so
// CheckPassword against an empty hash simply always fails.
func (m *Manager) ChangePassword(ctx context.Context, id int64, currentPassword, newPassword string) error {
	policy, err := m.store.GetPasswordPolicySettings(ctx)
	if err != nil {
		return fmt.Errorf("load password policy: %w", err)
	}
	if err := ValidatePassword(policy, newPassword); err != nil {
		return err
	}
	user, err := m.store.GetUserByID(ctx, id)
	if err != nil {
		return fmt.Errorf("look up user: %w", err)
	}
	if !CheckPassword(user.PasswordHash, currentPassword) {
		return ErrInvalidCredentials
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	return m.store.UpdateUserPassword(ctx, id, hash)
}

// resolveRole maps a set of directory/IdP groups to a panel role by
// checking them against the admin-managed auth_group_rules list for this
// method. ok=false means no group matched either role's list -- the
// caller must deny the login outright (ErrNoGroupMatch), not fall back to
// a default role. Admin rules are checked first so a group listed under
// both roles (misconfiguration) resolves to the more privileged one.
func (m *Manager) resolveRole(ctx context.Context, method string, groups []string) (role string, ok bool, err error) {
	rules, err := m.store.ListAuthGroupRules(ctx, method)
	if err != nil {
		return "", false, fmt.Errorf("load %s group rules: %w", method, err)
	}
	role, ok = resolveRoleFromRules(rules, groups)
	return role, ok, nil
}

// resolveRoleFromRules is the pure matching logic behind resolveRole, split
// out so it's unit-testable without a database: does any of groups appear
// in rules? Admin rules are checked first, so a group listed under both
// roles (misconfiguration) resolves to the more privileged one.
func resolveRoleFromRules(rules []store.AuthGroupRule, groups []string) (role string, ok bool) {
	for _, checkRole := range []string{"admin", "user"} {
		for _, rule := range rules {
			if rule.Role != checkRole {
				continue
			}
			for _, g := range groups {
				if g == rule.GroupValue {
					return checkRole, true
				}
			}
		}
	}
	return "", false
}

// FinishExternalLogin is the shared tail for LDAP and OIDC logins, which
// differ only in how they obtain (username, groups): resolve the role from
// group membership, JIT-provision or update the account, then issue a
// session exactly like the local-password path's createSession -- external
// logins skip TOTP entirely (the directory/IdP owns its own MFA).
func (m *Manager) FinishExternalLogin(ctx context.Context, method, username string, groups []string) (token string, expiresAt time.Time, err error) {
	role, ok, err := m.resolveRole(ctx, method, groups)
	if err != nil {
		return "", time.Time{}, err
	}
	if !ok {
		return "", time.Time{}, ErrNoGroupMatch
	}
	user, err := m.store.UpsertExternalUser(ctx, username, method, role)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("provision external user: %w", err)
	}
	if err := checkAccountLoginAllowed(user); err != nil {
		return "", time.Time{}, err
	}
	return m.createSession(ctx, user.ID)
}
