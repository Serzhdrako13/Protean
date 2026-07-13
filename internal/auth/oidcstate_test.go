package auth

import (
	"testing"
	"time"
)

func TestOIDCStateRoundTrip(t *testing.T) {
	o := NewOIDCState("session-secret")
	tok := o.Issue("verifier-123", "nonce-abc")

	verifier, nonce, ok := o.Verify(tok)
	if !ok || verifier != "verifier-123" || nonce != "nonce-abc" {
		t.Fatalf("Verify = %q,%q,%v; want verifier-123,nonce-abc,true", verifier, nonce, ok)
	}
}

func TestOIDCStateRejectsTamperAndWrongSecret(t *testing.T) {
	o := NewOIDCState("secret-a")
	tok := o.Issue("verifier", "nonce")

	b := []byte(tok)
	b[len(b)-1] ^= 0x01
	if _, _, ok := o.Verify(string(b)); ok {
		t.Error("tampered token verified")
	}

	if _, _, ok := NewOIDCState("secret-b").Verify(tok); ok {
		t.Error("token verified under a different secret")
	}

	if _, _, ok := o.Verify("garbage"); ok {
		t.Error("garbage verified")
	}
}

func TestOIDCStateExpiry(t *testing.T) {
	o := NewOIDCState("session-secret")
	o.ttl = -1 * time.Second // already expired the instant it's issued
	tok := o.Issue("verifier", "nonce")

	if _, _, ok := o.Verify(tok); ok {
		t.Error("expired state token verified")
	}
}
