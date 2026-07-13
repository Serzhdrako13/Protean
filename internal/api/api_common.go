package api

import (
	"context"
	"encoding/json"
	"net/http"
)

// apiEnvelope is the JSON response shape for every /api/* endpoint, matching
// 3x-ui's frontend convention ({success, msg, obj}) so the SPA's HTTP client
// can be built the same way theirs is.
type apiEnvelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg,omitempty"`
	Obj     any    `json:"obj,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, env apiEnvelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func writeOK(w http.ResponseWriter, obj any) {
	writeJSON(w, http.StatusOK, apiEnvelope{Success: true, Obj: obj})
}

func writeOKMsg(w http.ResponseWriter, msg string, obj any) {
	writeJSON(w, http.StatusOK, apiEnvelope{Success: true, Msg: msg, Obj: obj})
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiEnvelope{Success: false, Msg: msg})
}

// decodeJSON reads and closes the request body into v, or returns an error
// suitable for writeErr(w, http.StatusBadRequest, ...).
func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

// requireAuthAPI gates a JSON handler behind the session cookie + CSRF
// double-submit check; failures return a JSON 401/403 envelope instead of
// redirecting (a fetch() call can't follow a redirect usefully). A
// role=="user" session (portal-only account) is additionally confined to
// portalRoleAllowedPrefixes -- everything else 403s with X-Portal-Redirect
// so the admin SPA's client knows to bounce it to /portal instead of
// showing a bare error (role=="admin" is unrestricted, unchanged).
func (s *Server) requireAuthAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, msg(r, "not authenticated", "не выполнен вход"))
			return
		}
		userID, username, role, authSource, passwordChangedAt, err := s.auth.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			s.clearSessionCookie(w)
			writeErr(w, http.StatusUnauthorized, msg(r, "session expired", "сессия истекла"))
			return
		}
		if role == "user" && !portalRoleAllowed(r.URL.Path) {
			w.Header().Set("X-Portal-Redirect", "1")
			writeErr(w, http.StatusForbidden, msg(r, "user accounts can only access the self-service portal", "учётные записи пользователей могут пользоваться только порталом самообслуживания"))
			return
		}
		if s.isPasswordExpired(r.Context(), passwordChangedAt) && !passwordChangeAllowed(r.URL.Path) {
			w.Header().Set("X-Password-Expired", "1")
			writeErr(w, http.StatusForbidden, msg(r, "password expired, must be changed before continuing", "срок действия пароля истёк, необходимо сменить его, чтобы продолжить"))
			return
		}

		token := s.ensureCSRFCookie(w, r)
		if !isSafeMethod(r.Method) && !s.validCSRF(r, token) {
			writeErr(w, http.StatusForbidden, msg(r, "invalid or missing CSRF token", "неверный или отсутствующий CSRF-токен"))
			return
		}

		ctx := context.WithValue(r.Context(), usernameKey, username)
		ctx = context.WithValue(ctx, roleKey, role)
		ctx = context.WithValue(ctx, passwordChangedAtKey, passwordChangedAt)
		ctx = context.WithValue(ctx, userIDKey, userID)
		ctx = context.WithValue(ctx, authSourceKey, authSource)
		next(w, r.WithContext(ctx))
	}
}
