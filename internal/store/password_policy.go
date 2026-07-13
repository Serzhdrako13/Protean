package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// PasswordPolicySettings configures password strength/expiry requirements
// (see internal/auth's ValidatePassword and internal/api's requireAuthAPI
// expiry gate). Singleton, same convention as TLSState/LoginSecuritySettings.
type PasswordPolicySettings struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool
	// MaxAgeDays: 0 = no forced expiry.
	MaxAgeDays int
	// SessionTTLHours: how long a login session stays valid (was a
	// hardcoded 30-day constant -- see auth.SessionTTL).
	SessionTTLHours int
}

func defaultPasswordPolicySettings() PasswordPolicySettings {
	return PasswordPolicySettings{MinLength: 8, SessionTTLHours: 720}
}

func (s *Store) GetPasswordPolicySettings(ctx context.Context) (PasswordPolicySettings, error) {
	t := defaultPasswordPolicySettings()
	err := s.pool.QueryRow(ctx, `
		SELECT min_length, require_upper, require_lower, require_digit, require_symbol, max_age_days, session_ttl_hours
		FROM wgpanel.password_policy_settings WHERE id = true
	`).Scan(&t.MinLength, &t.RequireUpper, &t.RequireLower, &t.RequireDigit, &t.RequireSymbol, &t.MaxAgeDays, &t.SessionTTLHours)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	if err != nil {
		return PasswordPolicySettings{}, err
	}
	return t, nil
}

func (s *Store) SetPasswordPolicySettings(ctx context.Context, t PasswordPolicySettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.password_policy_settings (
			id, min_length, require_upper, require_lower, require_digit, require_symbol, max_age_days, session_ttl_hours, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (id) DO UPDATE SET
			min_length = EXCLUDED.min_length,
			require_upper = EXCLUDED.require_upper,
			require_lower = EXCLUDED.require_lower,
			require_digit = EXCLUDED.require_digit,
			require_symbol = EXCLUDED.require_symbol,
			max_age_days = EXCLUDED.max_age_days,
			session_ttl_hours = EXCLUDED.session_ttl_hours,
			updated_at = now()
	`, t.MinLength, t.RequireUpper, t.RequireLower, t.RequireDigit, t.RequireSymbol, t.MaxAgeDays, t.SessionTTLHours)
	return err
}
