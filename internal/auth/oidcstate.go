package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// OIDCState issues short-lived signed tokens carrying the PKCE verifier and
// nonce between the /api/auth/oidc/start redirect and the /callback
// handler -- mirrors PendingAuth's stateless signed-token idiom (HMAC over
// SESSION_SECRET) instead of a server-side session store, so the callback
// needs no lookup to validate it. The token itself IS the OAuth2 "state"
// parameter: its signature makes it unguessable/untamperable, exactly the
// CSRF property "state" is supposed to provide.
type OIDCState struct {
	secret []byte
	ttl    time.Duration
}

func NewOIDCState(sessionSecret string) *OIDCState {
	return &OIDCState{secret: []byte(sessionSecret), ttl: 10 * time.Minute}
}

// Issue returns a token binding verifier+nonce, valid for the configured TTL.
func (o *OIDCState) Issue(verifier, nonce string) string {
	exp := time.Now().Add(o.ttl).Unix()
	payload := strings.Join([]string{b64url(verifier), b64url(nonce), strconv.FormatInt(exp, 10)}, ".")
	return payload + "." + o.sign(payload)
}

// Verify checks the signature and expiry and returns the bound verifier+nonce.
func (o *OIDCState) Verify(token string) (verifier, nonce string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", false
	}
	payload := strings.Join(parts[:3], ".")
	if !hmac.Equal([]byte(parts[3]), []byte(o.sign(payload))) {
		return "", "", false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", "", false
	}
	v, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	n, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	return string(v), string(n), true
}

func (o *OIDCState) sign(payload string) string {
	mac := hmac.New(sha256.New, o.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
