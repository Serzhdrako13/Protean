package wgfamily

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeyPair creates a new WireGuard-compatible Curve25519 key pair,
// base64-encoded the same way `wg genkey`/`wg pubkey` produce.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("read random bytes: %w", err)
	}
	// Clamp per RFC 7748 / WireGuard convention.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}
