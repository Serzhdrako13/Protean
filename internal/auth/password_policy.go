package auth

import (
	"fmt"
	"unicode"

	"protean/internal/store"
)

// PolicyError is a password-validation failure carrying both an English and
// Russian rendering -- internal/auth has no *http.Request to derive a
// language from (see internal/api's requestLang), so the message pair
// travels on the error itself and the api layer picks one via
// PolicyErrorMessage, mirroring how RejectionMessage works for bruteforce.go.
type PolicyError struct {
	En, Ru string
}

func (e *PolicyError) Error() string { return e.En }

// PolicyErrorMessage picks En or Ru off a PolicyError for the given language
// ("en" or anything else -> Russian). Falls back to err.Error() for any
// other error type, so callers can use it unconditionally.
func PolicyErrorMessage(err error, lang string) string {
	if pe, ok := err.(*PolicyError); ok {
		if lang == "en" {
			return pe.En
		}
		return pe.Ru
	}
	return err.Error()
}

// ValidatePassword checks a candidate password against the admin-configured
// policy (see store.PasswordPolicySettings) -- the single validation point
// used by CreateUser/AdminSetPassword/ChangePassword below, replacing what
// used to be three copy-pasted `len(password) < 8` checks.
func ValidatePassword(policy store.PasswordPolicySettings, password string) error {
	if len(password) < policy.MinLength {
		return &PolicyError{
			En: fmt.Sprintf("password must be at least %d characters", policy.MinLength),
			Ru: fmt.Sprintf("пароль должен быть не короче %d символов", policy.MinLength),
		}
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		return &PolicyError{En: "password must include an uppercase letter", Ru: "пароль должен содержать заглавную букву"}
	}
	if policy.RequireLower && !hasLower {
		return &PolicyError{En: "password must include a lowercase letter", Ru: "пароль должен содержать строчную букву"}
	}
	if policy.RequireDigit && !hasDigit {
		return &PolicyError{En: "password must include a digit", Ru: "пароль должен содержать цифру"}
	}
	if policy.RequireSymbol && !hasSymbol {
		return &PolicyError{En: "password must include a symbol", Ru: "пароль должен содержать символ"}
	}
	return nil
}
