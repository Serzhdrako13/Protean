package api

import (
	"encoding/base64"
	"testing"
)

func TestValidWGPublicKey(t *testing.T) {
	// 32 zero bytes -> valid base64 key.
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if !validWGPublicKey(valid) {
		t.Errorf("expected %q to be valid", valid)
	}
	for _, bad := range []string{
		"",
		"not-base64!!",
		base64.StdEncoding.EncodeToString(make([]byte, 16)), // wrong length
		base64.StdEncoding.EncodeToString(make([]byte, 33)),
	} {
		if validWGPublicKey(bad) {
			t.Errorf("expected %q to be invalid", bad)
		}
	}
}

func TestPeerIDRoundTrip(t *testing.T) {
	// Standard-base64 wg key round-trips through the URL-safe encoding.
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	url, err := encodePeerID(key)
	if err != nil {
		t.Fatalf("encodePeerID: %v", err)
	}
	back, err := decodePeerID(url)
	if err != nil {
		t.Fatalf("decodePeerID: %v", err)
	}
	if back != key {
		t.Errorf("round trip: got %q want %q", back, key)
	}
}

// TestPeerIDRoundTripCertBasedName covers the bug this scheme exists to fix:
// cert-based providers (OpenVPN/IKEv2) use the plain client name (CN) as
// their Peer.PublicKey, not a WireGuard key -- the old code tried to
// base64-decode it as if it were one, which failed whenever the name's
// length wasn't a multiple of 4 (e.g. "sidorov", 7 chars), silently
// producing an unusable empty identifier instead of erroring loudly.
func TestPeerIDRoundTripCertBasedName(t *testing.T) {
	for _, name := range []string{"sidorov", "testuser", "a", "ab", "abc", "abcd", "жёлудь", "with.dots.in.it"} {
		url, err := encodePeerID(name)
		if err != nil {
			t.Fatalf("encodePeerID(%q): %v", name, err)
		}
		back, err := decodePeerID(url)
		if err != nil {
			t.Fatalf("decodePeerID(%q) (from %q): %v", url, name, err)
		}
		if back != name {
			t.Errorf("round trip for %q: got %q via url %q", name, back, url)
		}
	}
}

// TestDecodePeerIDBackwardCompat verifies an already-issued link (created
// before the "b."/"s." scheme prefix existed) still resolves correctly, so
// no migration of existing peer_owner.peer_key rows is needed.
func TestDecodePeerIDBackwardCompat(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("decode fixture key: %v", err)
	}
	oldStyleURLID := base64.RawURLEncoding.EncodeToString(raw) // no scheme prefix, as issued pre-fix

	back, err := decodePeerID(oldStyleURLID)
	if err != nil {
		t.Fatalf("decodePeerID(%q): %v", oldStyleURLID, err)
	}
	if back != key {
		t.Errorf("backward-compat decode: got %q want %q", back, key)
	}
}
