package auth

import "testing"

func TestTokenHasherIsKeyed(t *testing.T) {
	raw, hash, err := newTokenHasher("secret-a").generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if raw == "" || hash == "" {
		t.Fatal("empty token or hash")
	}

	// Same raw token hashed under the same secret is stable.
	if got := newTokenHasher("secret-a").hash(raw); got != hash {
		t.Errorf("hash not stable: %q != %q", got, hash)
	}

	// A different secret must produce a different hash -- otherwise the
	// secret isn't actually protecting the stored token.
	if got := newTokenHasher("secret-b").hash(raw); got == hash {
		t.Error("hash under a different secret matched -- secret not applied")
	}
}

func TestTokenHasherUnique(t *testing.T) {
	h := newTokenHasher("secret")
	_, hash1, _ := h.generate()
	_, hash2, _ := h.generate()
	if hash1 == hash2 {
		t.Error("two generated tokens collided")
	}
}
