package auth

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func testKeyHex(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return hex.EncodeToString(key)
}

func TestEncryptorRoundTrip(t *testing.T) {
	enc, err := NewEncryptor(testKeyHex(t))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}

	blob, err := enc.Seal("super-secret-private-key")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	plaintext, err := enc.Open(blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if plaintext != "super-secret-private-key" {
		t.Errorf("Open() = %q, want original plaintext", plaintext)
	}
}

func TestEncryptorRejectsTamperedBlob(t *testing.T) {
	enc, err := NewEncryptor(testKeyHex(t))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	blob, err := enc.Seal("secret")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	blob[len(blob)-1] ^= 0xFF

	if _, err := enc.Open(blob); err == nil {
		t.Error("Open should fail on tampered ciphertext")
	}
}

func TestNewEncryptorRejectsBadKey(t *testing.T) {
	if _, err := NewEncryptor("not-hex"); err == nil {
		t.Error("expected error for non-hex key")
	}
	if _, err := NewEncryptor("abcd"); err == nil {
		t.Error("expected error for short key")
	}
}
