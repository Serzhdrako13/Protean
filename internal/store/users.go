package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrNotFound = errors.New("not found")

type User struct {
	ID                int64
	Username          string
	PasswordHash      string
	Role              string
	// AuthSource is "local", "ldap", or "oidc" -- see migration 0038. LDAP/
	// OIDC accounts are separate entities from a local account of the same
	// username (auth_source is part of the uniqueness key, not username
	// alone), and never have a PasswordHash.
	AuthSource        string
	TOTPSecret        string
	TOTPEnabled       bool
	CreatedAt         time.Time
	PasswordChangedAt time.Time
	// Language is the account's saved UI language preference ("ru"/"en"),
	// empty if never set -- the frontend falls back to browser detection
	// in that case.
	Language string
	// Enabled: false blocks ALL login and (see api_users.go) revokes every
	// VPN peer this account owns. Distinct from PortalAccessEnabled below.
	Enabled bool
	// PortalAccessEnabled: false blocks only the self-service portal login
	// path (checked for role == "user" accounts); existing VPN peers keep
	// working. Meaningless for role == "admin" (never checked for them).
	PortalAccessEnabled bool
}

// CreateUser creates a local (password-based) account -- SeedAdmin and the
// admin "Users" page are its only callers, and both only ever create local
// accounts, so auth_source is hardcoded rather than threaded through as a
// parameter. LDAP/OIDC accounts are provisioned via UpsertExternalUser
// instead, on first successful external login.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.users (username, password_hash, role, auth_source)
		VALUES ($1, $2, $3, 'local')
		RETURNING id, username, password_hash, role, auth_source, created_at, password_changed_at
	`, username, passwordHash, role).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.AuthSource, &u.CreatedAt, &u.PasswordChangedAt)
	return u, err
}

// UpsertExternalUser JIT-provisions an LDAP/OIDC account on first login, or
// updates its role in place on every later login -- so a group-membership
// change in the directory takes effect on the user's next login without
// any admin action in the panel. Never touches password_hash (external
// accounts have none).
func (s *Store) UpsertExternalUser(ctx context.Context, username, authSource, role string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.users (username, role, auth_source)
		VALUES ($1, $2, $3)
		ON CONFLICT (auth_source, username) DO UPDATE SET role = EXCLUDED.role
		RETURNING id, username, role, auth_source, totp_secret, totp_enabled, created_at, password_changed_at, language, enabled, portal_access_enabled
	`, username, role, authSource).Scan(&u.ID, &u.Username, &u.Role, &u.AuthSource, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.PasswordChangedAt, &u.Language, &u.Enabled, &u.PortalAccessEnabled)
	return u, err
}

// GetUserByUsernameAndSource looks up an account scoped to one login
// method -- used only by the three login paths, each of which already
// knows which source it's checking. Every other lookup (self-service
// endpoints acting on "the current session's account") must use GetUserByID
// instead, since username alone no longer identifies a unique account.
func (s *Store) GetUserByUsernameAndSource(ctx context.Context, username, authSource string) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, COALESCE(password_hash, ''), role, auth_source, totp_secret, totp_enabled, created_at, password_changed_at, language, enabled, portal_access_enabled
		FROM protean.users
		WHERE username = $1 AND auth_source = $2
	`, username, authSource).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.AuthSource, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.PasswordChangedAt, &u.Language, &u.Enabled, &u.PortalAccessEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT id, username, COALESCE(password_hash, ''), role, auth_source, totp_secret, totp_enabled, created_at, password_changed_at, language, enabled, portal_access_enabled
		FROM protean.users
		WHERE id = $1
	`, id).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.AuthSource, &u.TOTPSecret, &u.TOTPEnabled, &u.CreatedAt, &u.PasswordChangedAt, &u.Language, &u.Enabled, &u.PortalAccessEnabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UpdateUserLanguage saves the account's UI language preference.
func (s *Store) UpdateUserLanguage(ctx context.Context, id int64, language string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.users SET language = $2 WHERE id = $1
	`, id, language)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListUsers returns every account, admins first then users, each group by
// username -- for the admin "Users" management page.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, username, role, created_at, enabled, portal_access_enabled FROM protean.users
		ORDER BY role DESC, username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.Enabled, &u.PortalAccessEnabled); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserEnabled sets the account-wide enabled flag (see the migration
// that adds this column for what disabling implies).
func (s *Store) UpdateUserEnabled(ctx context.Context, id int64, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE protean.users SET enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateUserRole force-sets an account's role -- used by the emergency
// admin break-glass path (see internal/auth/manager.go's
// SeedEmergencyAdmin) to guarantee the account is an admin even if a
// pre-existing local account of the same username had drifted to "user".
func (s *Store) UpdateUserRole(ctx context.Context, id int64, role string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE protean.users SET role = $2 WHERE id = $1`, id, role)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateUserPortalAccess sets the portal-only access flag.
func (s *Store) UpdateUserPortalAccess(ctx context.Context, id int64, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE protean.users SET portal_access_enabled = $2 WHERE id = $1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CountUsersByRole is used to guard against deleting the last remaining admin.
func (s *Store) CountUsersByRole(ctx context.Context, role string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM protean.users WHERE role = $1`, role).Scan(&n)
	return n, err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM protean.users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserTOTP stores the secret and enabled flag for a user's 2FA.
func (s *Store) SetUserTOTP(ctx context.Context, id int64, secret string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.users SET totp_secret = $2, totp_enabled = $3 WHERE id = $1
	`, id, secret, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM protean.users`).Scan(&n)
	return n, err
}

func (s *Store) UpdateUserPassword(ctx context.Context, id int64, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.users SET password_hash = $2, password_changed_at = now() WHERE id = $1
	`, id, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
