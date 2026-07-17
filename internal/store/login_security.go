package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// LoginSecuritySettings configures the login brute-force guard (see
// internal/auth/bruteforce.go). Singleton, mirrors TLSState's convention.
type LoginSecuritySettings struct {
	Enabled                bool
	TrackByUsername        bool
	TrackByIP              bool
	FailThreshold          int
	CountWindowMinutes     int
	BanBaseMinutes         int
	EscalationFactor       float64
	EscalationResetMinutes int
	MaxBanMinutes          int
}

func defaultLoginSecuritySettings() LoginSecuritySettings {
	return LoginSecuritySettings{
		Enabled: true, TrackByUsername: true, TrackByIP: true,
		FailThreshold: 3, CountWindowMinutes: 5,
		BanBaseMinutes: 5, EscalationFactor: 2, EscalationResetMinutes: 60,
		MaxBanMinutes: 1440,
	}
}

// GetLoginSecuritySettings returns the current settings, defaulting (not
// erroring) when no row exists yet.
func (s *Store) GetLoginSecuritySettings(ctx context.Context) (LoginSecuritySettings, error) {
	t := defaultLoginSecuritySettings()
	err := s.pool.QueryRow(ctx, `
		SELECT enabled, track_by_username, track_by_ip, fail_threshold, count_window_minutes,
		       ban_base_minutes, escalation_factor, escalation_reset_minutes, max_ban_minutes
		FROM protean.login_security_settings WHERE id = true
	`).Scan(
		&t.Enabled, &t.TrackByUsername, &t.TrackByIP, &t.FailThreshold, &t.CountWindowMinutes,
		&t.BanBaseMinutes, &t.EscalationFactor, &t.EscalationResetMinutes, &t.MaxBanMinutes,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	if err != nil {
		return LoginSecuritySettings{}, err
	}
	return t, nil
}

// SetLoginSecuritySettings upserts the singleton row.
func (s *Store) SetLoginSecuritySettings(ctx context.Context, t LoginSecuritySettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.login_security_settings (
			id, enabled, track_by_username, track_by_ip, fail_threshold, count_window_minutes,
			ban_base_minutes, escalation_factor, escalation_reset_minutes, max_ban_minutes, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, now())
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			track_by_username = EXCLUDED.track_by_username,
			track_by_ip = EXCLUDED.track_by_ip,
			fail_threshold = EXCLUDED.fail_threshold,
			count_window_minutes = EXCLUDED.count_window_minutes,
			ban_base_minutes = EXCLUDED.ban_base_minutes,
			escalation_factor = EXCLUDED.escalation_factor,
			escalation_reset_minutes = EXCLUDED.escalation_reset_minutes,
			max_ban_minutes = EXCLUDED.max_ban_minutes,
			updated_at = now()
	`, t.Enabled, t.TrackByUsername, t.TrackByIP, t.FailThreshold, t.CountWindowMinutes,
		t.BanBaseMinutes, t.EscalationFactor, t.EscalationResetMinutes, t.MaxBanMinutes)
	return err
}

// LoginIPRule is one entry in the admin-managed allow/deny list.
type LoginIPRule struct {
	IPOrCIDR  string
	Kind      string // "allow" | "deny"
	Note      string
	CreatedAt time.Time
}

func (s *Store) ListLoginIPRules(ctx context.Context) ([]LoginIPRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip_or_cidr, kind, note, created_at FROM protean.login_ip_rules ORDER BY created_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginIPRule
	for rows.Next() {
		var r LoginIPRule
		if err := rows.Scan(&r.IPOrCIDR, &r.Kind, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddLoginIPRule(ctx context.Context, r LoginIPRule) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.login_ip_rules (ip_or_cidr, kind, note)
		VALUES ($1, $2, $3)
		ON CONFLICT (ip_or_cidr) DO UPDATE SET kind = EXCLUDED.kind, note = EXCLUDED.note
	`, r.IPOrCIDR, r.Kind, r.Note)
	return err
}

func (s *Store) DeleteLoginIPRule(ctx context.Context, ipOrCIDR string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.login_ip_rules WHERE ip_or_cidr = $1`, ipOrCIDR)
	return err
}

// RecordLoginAttempt appends to the append-only attempt log -- every
// attempt, successful or not, rejected-by-guard or actually checked against
// a password/TOTP code.
func (s *Store) RecordLoginAttempt(ctx context.Context, username, ip string, success bool, reason string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.login_attempts (username, ip, success, reason) VALUES ($1, $2, $3, $4)
	`, username, ip, success, reason)
	return err
}

// CountRecentFailures counts failed attempts for one key (username or IP)
// since the given time -- the sliding window the ban threshold is checked
// against.
func (s *Store) CountRecentFailures(ctx context.Context, keyType, keyValue string, since time.Time) (int, error) {
	col := "username"
	if keyType == "ip" {
		col = "ip"
	}
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM protean.login_attempts WHERE `+col+` = $1 AND success = false AND ts > $2`,
		keyValue, since,
	).Scan(&n)
	return n, err
}

// LoginBanState is one key's (username or IP) current/last ban.
type LoginBanState struct {
	KeyType         string
	KeyValue        string
	BannedUntil     time.Time
	EscalationLevel int
	UpdatedAt       time.Time
}

func (s *Store) GetLoginBanState(ctx context.Context, keyType, keyValue string) (LoginBanState, bool, error) {
	var b LoginBanState
	b.KeyType, b.KeyValue = keyType, keyValue
	err := s.pool.QueryRow(ctx, `
		SELECT banned_until, escalation_level, updated_at
		FROM protean.login_ban_state WHERE key_type = $1 AND key_value = $2
	`, keyType, keyValue).Scan(&b.BannedUntil, &b.EscalationLevel, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginBanState{}, false, nil
	}
	if err != nil {
		return LoginBanState{}, false, err
	}
	return b, true, nil
}

func (s *Store) UpsertLoginBanState(ctx context.Context, keyType, keyValue string, bannedUntil time.Time, escalationLevel int) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.login_ban_state (key_type, key_value, banned_until, escalation_level, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (key_type, key_value) DO UPDATE SET
			banned_until = EXCLUDED.banned_until,
			escalation_level = EXCLUDED.escalation_level,
			updated_at = now()
	`, keyType, keyValue, bannedUntil, escalationLevel)
	return err
}

// ClearLoginBanState lifts a ban immediately (admin "unban" action) --
// zeroes escalation too, a manual unban is a clean slate, not just "let
// back in early but still one violation away from the next escalated ban."
func (s *Store) ClearLoginBanState(ctx context.Context, keyType, keyValue string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.login_ban_state SET banned_until = now(), escalation_level = 0, updated_at = now()
		WHERE key_type = $1 AND key_value = $2
	`, keyType, keyValue)
	return err
}

// ListActiveLoginBans returns every key currently banned (banned_until in
// the future), for the admin bans view.
func (s *Store) ListActiveLoginBans(ctx context.Context) ([]LoginBanState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT key_type, key_value, banned_until, escalation_level, updated_at
		FROM protean.login_ban_state WHERE banned_until > now() ORDER BY banned_until DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginBanState
	for rows.Next() {
		var b LoginBanState
		if err := rows.Scan(&b.KeyType, &b.KeyValue, &b.BannedUntil, &b.EscalationLevel, &b.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// LoginAttemptRow is one row of the raw attempt log, for the admin stats/
// recent-activity view.
type LoginAttemptRow struct {
	TS       time.Time
	Username string
	IP       string
	Success  bool
	Reason   string
}

// ListRecentLoginAttempts returns the most recent attempts, newest first,
// bounded by limit.
func (s *Store) ListRecentLoginAttempts(ctx context.Context, limit int) ([]LoginAttemptRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, username, ip, success, reason FROM protean.login_attempts
		ORDER BY ts DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LoginAttemptRow
	for rows.Next() {
		var a LoginAttemptRow
		if err := rows.Scan(&a.TS, &a.Username, &a.IP, &a.Success, &a.Reason); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// LoginAttemptStats summarizes attempt volume since a cutoff, for the admin
// stats view.
type LoginAttemptStats struct {
	TotalAttempts  int
	FailedAttempts int
	TopIPs         []struct {
		IP    string
		Count int
	}
}

// GetLoginAttemptStats aggregates attempts since the given time: totals plus
// the top-N offending IPs by failure count.
func (s *Store) GetLoginAttemptStats(ctx context.Context, since time.Time, topN int) (LoginAttemptStats, error) {
	var stats LoginAttemptStats
	err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE NOT success)
		FROM protean.login_attempts WHERE ts > $1
	`, since).Scan(&stats.TotalAttempts, &stats.FailedAttempts)
	if err != nil {
		return LoginAttemptStats{}, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT ip, count(*) FROM protean.login_attempts
		WHERE ts > $1 AND NOT success AND ip != ''
		GROUP BY ip ORDER BY count(*) DESC LIMIT $2
	`, since, topN)
	if err != nil {
		return LoginAttemptStats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			return LoginAttemptStats{}, err
		}
		stats.TopIPs = append(stats.TopIPs, struct {
			IP    string
			Count int
		}{ip, count})
	}
	return stats, rows.Err()
}
