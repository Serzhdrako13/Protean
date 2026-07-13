package api

import (
	"context"
	"net/http"
	"time"

	"protean/internal/store"
)

// isPasswordExpired reports whether changedAt is older than the currently
// configured max_age_days (0 = expiry disabled). Queried once per
// authenticated request -- a cheap singleton-row SELECT, consistent with
// how the rest of this codebase reads small admin-config tables (no
// dedicated cache layer exists here, and this panel's traffic doesn't
// warrant one).
func (s *Server) isPasswordExpired(ctx context.Context, changedAt time.Time) bool {
	policy, err := s.store.GetPasswordPolicySettings(ctx)
	if err != nil || policy.MaxAgeDays <= 0 {
		return false
	}
	return time.Since(changedAt) > time.Duration(policy.MaxAgeDays)*24*time.Hour
}

type apiPasswordPolicySettings struct {
	MinLength       int  `json:"min_length"`
	RequireUpper    bool `json:"require_upper"`
	RequireLower    bool `json:"require_lower"`
	RequireDigit    bool `json:"require_digit"`
	RequireSymbol   bool `json:"require_symbol"`
	MaxAgeDays      int  `json:"max_age_days"`
	SessionTTLHours int  `json:"session_ttl_hours"`
}

// GET /api/password-policy/settings
func (s *Server) apiPasswordPolicyGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetPasswordPolicySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiPasswordPolicySettings(t))
}

// PUT /api/password-policy/settings
func (s *Server) apiPasswordPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiPasswordPolicySettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.MinLength < 1 {
		writeErr(w, http.StatusBadRequest, msg(r, "min_length must be at least 1", "min_length должно быть не менее 1"))
		return
	}
	if req.MaxAgeDays < 0 {
		writeErr(w, http.StatusBadRequest, msg(r, "max_age_days must be 0 (disabled) or positive", "max_age_days должно быть 0 (отключено) либо положительным числом"))
		return
	}
	if req.SessionTTLHours < 1 {
		writeErr(w, http.StatusBadRequest, msg(r, "session_ttl_hours must be at least 1", "session_ttl_hours должно быть не менее 1"))
		return
	}
	if err := s.store.SetPasswordPolicySettings(r.Context(), store.PasswordPolicySettings(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "password_policy.update", "")
	writeOK(w, nil)
}
