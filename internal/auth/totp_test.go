package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPGenerateAndValidate(t *testing.T) {
	secret, url, err := GenerateTOTPSecret("admin")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if secret == "" || url == "" {
		t.Fatal("empty secret or url")
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Error("valid code rejected")
	}
	if ValidateTOTP(secret, "000000") {
		t.Error("bogus code accepted (or unlucky match)")
	}
}
