package auth

import "testing"

func TestPendingAuthRoundTrip(t *testing.T) {
	p := NewPendingAuth("session-secret")
	tok := p.Issue("admin")

	got, ok := p.Verify(tok)
	if !ok || got != "admin" {
		t.Fatalf("Verify = %q,%v; want admin,true", got, ok)
	}
}

func TestPendingAuthRejectsTamperAndWrongSecret(t *testing.T) {
	p := NewPendingAuth("secret-a")
	tok := p.Issue("admin")

	// Tamper the signature.
	b := []byte(tok)
	b[len(b)-1] ^= 0x01
	if _, ok := p.Verify(string(b)); ok {
		t.Error("tampered token verified")
	}

	// Different secret must not verify (can't forge the password step).
	if _, ok := NewPendingAuth("secret-b").Verify(tok); ok {
		t.Error("token verified under a different secret")
	}

	if _, ok := p.Verify("garbage"); ok {
		t.Error("garbage verified")
	}
}
