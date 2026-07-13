package auth

import (
	"context"
	"fmt"

	"github.com/pquerna/otp/totp"
)

const totpIssuer = "Protean"

// GenerateTOTPSecret creates a new TOTP secret and its otpauth:// URL (for
// rendering a QR code) for the given account. The secret is not persisted
// until the user confirms a code via EnableTOTP.
func GenerateTOTPSecret(account string) (secret, url string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: account,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP reports whether code is currently valid for secret.
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// EnableTOTP turns on 2FA for a user after they prove possession of the
// secret with a valid code. id is the session's user ID (TOTP is only ever
// relevant for auth_source=="local" accounts, since external logins skip
// it entirely -- see Manager.FinishExternalLogin).
func (m *Manager) EnableTOTP(ctx context.Context, id int64, secret, code string) error {
	if !ValidateTOTP(secret, code) {
		return fmt.Errorf("invalid code")
	}
	return m.store.SetUserTOTP(ctx, id, secret, true)
}

// DisableTOTP turns off 2FA, requiring the current password to do so.
func (m *Manager) DisableTOTP(ctx context.Context, id int64, password string) error {
	user, err := m.store.GetUserByID(ctx, id)
	if err != nil {
		return fmt.Errorf("look up user: %w", err)
	}
	if !CheckPassword(user.PasswordHash, password) {
		return ErrInvalidCredentials
	}
	return m.store.SetUserTOTP(ctx, id, "", false)
}

// TOTPEnabled reports whether a user currently has 2FA on.
func (m *Manager) TOTPEnabled(ctx context.Context, id int64) (bool, error) {
	user, err := m.store.GetUserByID(ctx, id)
	if err != nil {
		return false, err
	}
	return user.TOTPEnabled, nil
}
