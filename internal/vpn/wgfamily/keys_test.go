package wgfamily

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key length = %d, want 32", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubBytes))
	}

	priv2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (2nd): %v", err)
	}
	if priv == priv2 {
		t.Error("two calls to GenerateKeyPair produced the same private key")
	}
}
