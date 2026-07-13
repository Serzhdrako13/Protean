package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// tokenHasher turns a raw session token into the value stored in the
// database. It's an HMAC keyed by SESSION_SECRET, not a bare hash: a leaked
// `sessions` row plus the token algorithm still can't be turned into a valid
// cookie without the secret, which lives only in the panel's environment.
type tokenHasher struct {
	secret []byte
}

func newTokenHasher(secret string) tokenHasher {
	return tokenHasher{secret: []byte(secret)}
}

// generate returns a random URL-safe token to hand to the browser, and its
// keyed hash to store in the database.
func (h tokenHasher) generate() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("read random bytes: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, h.hash(raw), nil
}

func (h tokenHasher) hash(raw string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}
