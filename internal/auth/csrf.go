package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// CSRF issues and verifies stateless double-submit CSRF tokens. A token is
// `<nonce>.<hmac(nonce)>`, signed with SESSION_SECRET. The same value is set
// as a cookie and embedded in each form; on a state-changing request the two
// must match and the signature must verify -- a cross-site page can't read
// the cookie to forge a matching form field.
type CSRF struct {
	secret []byte
}

func NewCSRF(sessionSecret string) *CSRF {
	return &CSRF{secret: []byte(sessionSecret)}
}

func (c *CSRF) Issue() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	n := base64.RawURLEncoding.EncodeToString(nonce)
	return n + "." + c.sign(n), nil
}

// Valid reports whether token is well-formed and correctly signed.
func (c *CSRF) Valid(token string) bool {
	nonce, sig, ok := strings.Cut(token, ".")
	if !ok || nonce == "" || sig == "" {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(c.sign(nonce)))
}

// Match reports whether two tokens are equal in constant time (the
// double-submit check: cookie value vs form/header value).
func (c *CSRF) Match(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (c *CSRF) sign(nonce string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
