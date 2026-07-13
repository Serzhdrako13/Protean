package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	cookieName     = "protean_session"
	csrfCookieName = "protean_csrf"
	csrfFormField  = "csrf_token"
	csrfHeader     = "X-CSRF-Token"
)

type ctxKey int

const (
	usernameKey ctxKey = iota
	roleKey
	passwordChangedAtKey
	userIDKey
	authSourceKey
)

func usernameFromContext(ctx context.Context) string {
	u, _ := ctx.Value(usernameKey).(string)
	return u
}

func roleFromContext(ctx context.Context) string {
	r, _ := ctx.Value(roleKey).(string)
	return r
}

// userIDFromContext is the identifier self-service endpoints must use
// instead of username: since auth_source+username (not username alone) is
// unique, a bare username can no longer be trusted to resolve back to one
// account.
func userIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userIDKey).(int64)
	return id
}

func authSourceFromContext(ctx context.Context) string {
	a, _ := ctx.Value(authSourceKey).(string)
	return a
}

func passwordChangedAtFromContext(ctx context.Context) time.Time {
	t, _ := ctx.Value(passwordChangedAtKey).(time.Time)
	return t
}

// portalRoleAllowedPrefixes are the only paths a role=="user" session may
// reach -- everything else is the admin panel. /api/account (password/2FA)
// and /api/logout are reused as-is rather than duplicated under /api/portal.
var portalRoleAllowedPrefixes = []string{"/api/portal/", "/api/account", "/api/logout"}

func portalRoleAllowed(path string) bool {
	for _, p := range portalRoleAllowedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// passwordChangeAllowed reuses portalRoleAllowedPrefixes for the password-
// expiry gate too (not a separate, narrower list): a role=="user" session's
// own probe (GET /api/portal/me) must keep working while expired so the
// portal SPA can show "please change your password" instead of mistaking
// the resulting 403 for "not logged in" -- and for role=="admin" sessions
// this changes nothing in practice, since the admin SPA never calls
// /api/portal/* anyway (it's still effectively confined to
// /api/account + /api/logout for everything it actually uses).
func passwordChangeAllowed(path string) bool {
	return portalRoleAllowed(path)
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// ensureCSRFCookie returns the request's CSRF token, minting and setting a
// new one if the cookie is missing or invalid.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && s.csrf.Valid(c.Value) {
		return c.Value
	}
	token, err := s.csrf.Issue()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // read by nothing but our own forms; not a session secret
		Secure:   !s.cookieInsecure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// validCSRF checks that the submitted token (form field or header) matches
// the cookie and is a validly signed token.
func (s *Server) validCSRF(r *http.Request, cookieToken string) bool {
	submitted := r.Header.Get(csrfHeader)
	if submitted == "" {
		submitted = r.FormValue(csrfFormField)
	}
	return s.csrf.Valid(submitted) && s.csrf.Match(cookieToken, submitted)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   !s.cookieInsecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.cookieInsecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clientIP returns the caller's IP for rate-limiting and audit. It honors
// X-Forwarded-For ONLY when the panel is configured to sit behind a trusted
// proxy (SetTrustProxy); otherwise the header is attacker-controlled and would
// let a client forge its IP to dodge the login rate-limit or poison the audit
// log, so the real socket address is used.
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isSecure reports whether this request arrived over an encrypted
// connection -- either directly (r.TLS set, the panel's own web-TLS
// listener terminated it, see internal/webtls) or, when configured to sit
// behind a trusted reverse proxy (SetTrustProxy, "proxy" TLS mode), via
// X-Forwarded-Proto from that proxy. Same trust boundary as clientIP: the
// header is only honored when trustProxy is on, since it's otherwise
// attacker-controlled. Drives the frontend's "insecure connection" banner
// (see apiCSRF) -- not a security control itself, just a visibility signal.
func (s *Server) isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.trustProxy {
		return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	}
	return false
}
