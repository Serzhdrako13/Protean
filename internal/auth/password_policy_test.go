package auth

import (
	"testing"

	"protean/internal/store"
)

func TestValidatePasswordMinLength(t *testing.T) {
	policy := store.PasswordPolicySettings{MinLength: 8}
	if err := ValidatePassword(policy, "short12"); err == nil {
		t.Error("7-char password should fail an 8-char minimum")
	}
	if err := ValidatePassword(policy, "longenough1"); err != nil {
		t.Errorf("11-char password should pass an 8-char minimum: %v", err)
	}
}

func TestValidatePasswordComplexity(t *testing.T) {
	policy := store.PasswordPolicySettings{
		MinLength: 8, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true,
	}
	cases := []struct {
		password string
		wantOK   bool
	}{
		{"alllowercase1!", false}, // no uppercase
		{"ALLUPPERCASE1!", false}, // no lowercase
		{"NoDigitsHere!!", false}, // no digit
		{"NoSymbolsHere1", false}, // no symbol
		{"Valid1Password!", true},
	}
	for _, c := range cases {
		err := ValidatePassword(policy, c.password)
		if (err == nil) != c.wantOK {
			t.Errorf("ValidatePassword(%q) err=%v, want ok=%v", c.password, err, c.wantOK)
		}
	}
}

func TestValidatePasswordNoRequirementsJustLength(t *testing.T) {
	policy := store.PasswordPolicySettings{MinLength: 8}
	if err := ValidatePassword(policy, "simplepassword"); err != nil {
		t.Errorf("plain lowercase password should pass when no complexity is required: %v", err)
	}
}
