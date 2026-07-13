package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DataRetentionSettings configures opt-in auto-cleanup for data that
// otherwise accumulates without bound (see the migration that creates
// data_retention_settings for exactly what's eligible per category).
// Singleton, same convention as PasswordPolicySettings/TLSState.
type DataRetentionSettings struct {
	AccessRequestsEnabled bool
	AccessRequestsDays    int
	AuditLogEnabled       bool
	AuditLogDays          int
	LoginAttemptsEnabled  bool
	LoginAttemptsDays     int
	LoginBansEnabled      bool
	LoginBansDays         int
}

func defaultDataRetentionSettings() DataRetentionSettings {
	return DataRetentionSettings{
		AccessRequestsDays: 90,
		AuditLogDays:       365,
		LoginAttemptsDays:  30,
		LoginBansDays:      90,
	}
}

func (s *Store) GetDataRetentionSettings(ctx context.Context) (DataRetentionSettings, error) {
	t := defaultDataRetentionSettings()
	err := s.pool.QueryRow(ctx, `
		SELECT access_requests_enabled, access_requests_days, audit_log_enabled, audit_log_days,
		       login_attempts_enabled, login_attempts_days, login_bans_enabled, login_bans_days
		FROM wgpanel.data_retention_settings WHERE id = true
	`).Scan(
		&t.AccessRequestsEnabled, &t.AccessRequestsDays, &t.AuditLogEnabled, &t.AuditLogDays,
		&t.LoginAttemptsEnabled, &t.LoginAttemptsDays, &t.LoginBansEnabled, &t.LoginBansDays,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	if err != nil {
		return DataRetentionSettings{}, err
	}
	return t, nil
}

func (s *Store) SetDataRetentionSettings(ctx context.Context, t DataRetentionSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.data_retention_settings (
			id, access_requests_enabled, access_requests_days, audit_log_enabled, audit_log_days,
			login_attempts_enabled, login_attempts_days, login_bans_enabled, login_bans_days, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (id) DO UPDATE SET
			access_requests_enabled = EXCLUDED.access_requests_enabled,
			access_requests_days = EXCLUDED.access_requests_days,
			audit_log_enabled = EXCLUDED.audit_log_enabled,
			audit_log_days = EXCLUDED.audit_log_days,
			login_attempts_enabled = EXCLUDED.login_attempts_enabled,
			login_attempts_days = EXCLUDED.login_attempts_days,
			login_bans_enabled = EXCLUDED.login_bans_enabled,
			login_bans_days = EXCLUDED.login_bans_days,
			updated_at = now()
	`, t.AccessRequestsEnabled, t.AccessRequestsDays, t.AuditLogEnabled, t.AuditLogDays,
		t.LoginAttemptsEnabled, t.LoginAttemptsDays, t.LoginBansEnabled, t.LoginBansDays)
	return err
}

// DeleteOldDeniedAccessRequests removes 'denied' requests last touched
// before cutoff. Never touches pending/approved/granted rows regardless of
// age -- those are either in-progress or an active grant.
func (s *Store) DeleteOldDeniedAccessRequests(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM wgpanel.access_request WHERE status = 'denied' AND updated_at < $1
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteOldAuditEntries removes audit log rows older than cutoff.
func (s *Store) DeleteOldAuditEntries(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.audit_log WHERE ts < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteOldLoginAttempts removes login attempt log rows older than cutoff.
func (s *Store) DeleteOldLoginAttempts(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.login_attempts WHERE ts < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteStaleLoginBanState removes ban-state rows whose banned_until is
// before cutoff -- cutoff is always in the past (now minus a retention
// window), so a currently-active or future ban (banned_until still ahead of
// "now") can never match, regardless of how this is called.
func (s *Store) DeleteStaleLoginBanState(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.login_ban_state WHERE banned_until < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
