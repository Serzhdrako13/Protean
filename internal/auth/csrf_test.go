package auth

import "testing"

func TestCSRFIssueValid(t *testing.T) {
	c := NewCSRF("session-secret")
	tok, err := c.Issue()
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !c.Valid(tok) {
		t.Error("freshly issued token failed Valid")
	}
}

func TestCSRFRejectsTampered(t *testing.T) {
	c := NewCSRF("session-secret")
	tok, _ := c.Issue()

	// Flip a byte in the signature part.
	b := []byte(tok)
	b[len(b)-1] ^= 0x01
	if c.Valid(string(b)) {
		t.Error("tampered token passed Valid")
	}

	if c.Valid("no-dot-here") {
		t.Error("malformed token passed Valid")
	}
	if c.Valid("") {
		t.Error("empty token passed Valid")
	}
}

func TestCSRFRejectsWrongSecret(t *testing.T) {
	tok, _ := NewCSRF("secret-a").Issue()
	if NewCSRF("secret-b").Valid(tok) {
		t.Error("token validated under a different secret")
	}
}

func TestCSRFMatch(t *testing.T) {
	c := NewCSRF("s")
	if !c.Match("abc", "abc") {
		t.Error("equal tokens should match")
	}
	if c.Match("abc", "abd") {
		t.Error("different tokens should not match")
	}
	if c.Match("", "") {
		t.Error("empty tokens must not match")
	}
}
