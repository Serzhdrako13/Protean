package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// PendingAuth issues short-lived signed tokens that carry a username between
// the password step and the TOTP step of login. Signed with SESSION_SECRET,
// so a client cannot jump to the 2FA step (or change the username) without
// having passed the password check that minted the token.
type PendingAuth struct {
	secret []byte
	ttl    time.Duration
}

func NewPendingAuth(sessionSecret string) *PendingAuth {
	return &PendingAuth{secret: []byte(sessionSecret), ttl: 5 * time.Minute}
}

// Issue returns a token binding username, valid for the configured TTL.
func (p *PendingAuth) Issue(username string) string {
	exp := time.Now().Add(p.ttl).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(username)) + "." + strconv.FormatInt(exp, 10)
	return payload + "." + p.sign(payload)
}

// Verify checks the signature and expiry and returns the bound username.
func (p *PendingAuth) Verify(token string) (string, bool) {
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return "", false
	}
	payload, sig := token[:i], token[i+1:]
	if !hmac.Equal([]byte(sig), []byte(p.sign(payload))) {
		return "", false
	}
	userB64, expStr, ok := strings.Cut(payload, ".")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	user, err := base64.RawURLEncoding.DecodeString(userB64)
	if err != nil {
		return "", false
	}
	return string(user), true
}

func (p *PendingAuth) sign(payload string) string {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
