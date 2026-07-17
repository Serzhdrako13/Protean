package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	UserID            int64
	Username          string
	Role              string
	AuthSource        string
	ExpiresAt         time.Time
	PasswordChangedAt time.Time
}

func (s *Store) CreateSession(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)
	return err
}

// GetSession returns the session for tokenHash, provided it hasn't expired
// and the account is still allowed to be logged in -- enabled = false
// (account disabled) invalidates every existing session immediately for
// any role; portal_access_enabled = false does the same but only for
// role = 'user' sessions (an admin session is never affected by it). This
// means disabling/denying an account kicks an already-active session on
// its very next request, not just blocks future logins.
func (s *Store) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		SELECT s.user_id, u.username, u.role, u.auth_source, s.expires_at, u.password_changed_at
		FROM protean.sessions s
		JOIN protean.users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()
		  AND u.enabled = true
		  AND (u.role <> 'user' OR u.portal_access_enabled = true)
	`, tokenHash).Scan(&sess.UserID, &sess.Username, &sess.Role, &sess.AuthSource, &sess.ExpiresAt, &sess.PasswordChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return sess, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.sessions WHERE expires_at <= now()`)
	return err
}
