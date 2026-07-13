package api

import (
	"net/http"
	"strings"
	"time"

	"protean/internal/store"
)

type apiLoginSecuritySettings struct {
	Enabled                bool    `json:"enabled"`
	TrackByUsername        bool    `json:"track_by_username"`
	TrackByIP              bool    `json:"track_by_ip"`
	FailThreshold          int     `json:"fail_threshold"`
	CountWindowMinutes     int     `json:"count_window_minutes"`
	BanBaseMinutes         int     `json:"ban_base_minutes"`
	EscalationFactor       float64 `json:"escalation_factor"`
	EscalationResetMinutes int     `json:"escalation_reset_minutes"`
	MaxBanMinutes          int     `json:"max_ban_minutes"`
}

// GET /api/login-security/settings
func (s *Server) apiLoginSecuritySettingsGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetLoginSecuritySettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiLoginSecuritySettings(t))
}

// PUT /api/login-security/settings
func (s *Server) apiLoginSecuritySettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiLoginSecuritySettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.FailThreshold < 1 {
		writeErr(w, http.StatusBadRequest, msg(r, "fail_threshold must be at least 1", "fail_threshold должен быть не менее 1"))
		return
	}
	if req.CountWindowMinutes < 1 || req.BanBaseMinutes < 1 || req.MaxBanMinutes < 1 {
		writeErr(w, http.StatusBadRequest, msg(r, "durations must be at least 1 minute", "длительности должны быть не менее 1 минуты"))
		return
	}
	if req.EscalationFactor < 1 {
		writeErr(w, http.StatusBadRequest, msg(r, "escalation_factor must be at least 1", "escalation_factor должен быть не менее 1"))
		return
	}
	if err := s.store.SetLoginSecuritySettings(r.Context(), store.LoginSecuritySettings(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "login_security.settings.update", "")
	writeOK(w, nil)
}

type apiLoginIPRule struct {
	IPOrCIDR  string    `json:"ip_or_cidr"`
	Kind      string    `json:"kind"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// GET /api/login-security/ip-rules
func (s *Server) apiLoginIPRulesList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListLoginIPRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiLoginIPRule, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiLoginIPRule(row))
	}
	writeOK(w, out)
}

// POST /api/login-security/ip-rules
func (s *Server) apiLoginIPRulesAdd(w http.ResponseWriter, r *http.Request) {
	var req apiLoginIPRule
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	req.IPOrCIDR = strings.TrimSpace(req.IPOrCIDR)
	if req.IPOrCIDR == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "ip_or_cidr is required", "необходимо указать ip_or_cidr"))
		return
	}
	if req.Kind != "allow" && req.Kind != "deny" {
		writeErr(w, http.StatusBadRequest, msg(r, "kind must be \"allow\" or \"deny\"", "kind должен быть \"allow\" или \"deny\""))
		return
	}
	if err := s.store.AddLoginIPRule(r.Context(), store.LoginIPRule{
		IPOrCIDR: req.IPOrCIDR, Kind: req.Kind, Note: strings.TrimSpace(req.Note),
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "login_security.ip_rule.add", req.Kind+" "+req.IPOrCIDR)
	writeOK(w, nil)
}

// DELETE /api/login-security/ip-rules?ip_or_cidr=... -- takes the value as
// a query parameter rather than a URL path segment: a CIDR like
// "10.0.0.0/24" contains a slash, which would otherwise be split as a path
// segment by the router.
func (s *Server) apiLoginIPRulesDelete(w http.ResponseWriter, r *http.Request) {
	ipOrCIDR := r.URL.Query().Get("ip_or_cidr")
	if ipOrCIDR == "" {
		writeErr(w, http.StatusBadRequest, msg(r, "ip_or_cidr is required", "необходимо указать ip_or_cidr"))
		return
	}
	if err := s.store.DeleteLoginIPRule(r.Context(), ipOrCIDR); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "login_security.ip_rule.delete", ipOrCIDR)
	writeOK(w, nil)
}

type apiLoginBan struct {
	KeyType         string    `json:"key_type"`
	KeyValue        string    `json:"key_value"`
	BannedUntil     time.Time `json:"banned_until"`
	EscalationLevel int       `json:"escalation_level"`
}

// GET /api/login-security/bans
func (s *Server) apiLoginBansList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.store.ListActiveLoginBans(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiLoginBan, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiLoginBan{
			KeyType: row.KeyType, KeyValue: row.KeyValue,
			BannedUntil: row.BannedUntil, EscalationLevel: row.EscalationLevel,
		})
	}
	writeOK(w, out)
}

type apiLoginBanUnbanReq struct {
	KeyType  string `json:"key_type"`
	KeyValue string `json:"key_value"`
}

// POST /api/login-security/bans/unban
func (s *Server) apiLoginBansUnban(w http.ResponseWriter, r *http.Request) {
	var req apiLoginBanUnbanReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	if req.KeyType != "username" && req.KeyType != "ip" {
		writeErr(w, http.StatusBadRequest, msg(r, "key_type must be \"username\" or \"ip\"", "key_type должен быть \"username\" или \"ip\""))
		return
	}
	if err := s.store.ClearLoginBanState(r.Context(), req.KeyType, req.KeyValue); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "login_security.ban.clear", req.KeyType+" "+req.KeyValue)
	writeOK(w, nil)
}

type apiLoginAttempt struct {
	TS       time.Time `json:"ts"`
	Username string    `json:"username"`
	IP       string    `json:"ip"`
	Success  bool      `json:"success"`
	Reason   string    `json:"reason"`
}

type apiLoginStats struct {
	TotalAttempts24h  int               `json:"total_attempts_24h"`
	FailedAttempts24h int               `json:"failed_attempts_24h"`
	TopIPs            []apiLoginTopIP   `json:"top_ips_24h"`
	Recent            []apiLoginAttempt `json:"recent"`
}

type apiLoginTopIP struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// GET /api/login-security/stats
func (s *Server) apiLoginSecurityStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agg, err := s.store.GetLoginAttemptStats(ctx, time.Now().Add(-24*time.Hour), 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	recentRows, err := s.store.ListRecentLoginAttempts(ctx, 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	out := apiLoginStats{
		TotalAttempts24h: agg.TotalAttempts, FailedAttempts24h: agg.FailedAttempts,
		TopIPs: make([]apiLoginTopIP, 0, len(agg.TopIPs)),
		Recent: make([]apiLoginAttempt, 0, len(recentRows)),
	}
	for _, ip := range agg.TopIPs {
		out.TopIPs = append(out.TopIPs, apiLoginTopIP{IP: ip.IP, Count: ip.Count})
	}
	for _, a := range recentRows {
		out.Recent = append(out.Recent, apiLoginAttempt(a))
	}
	writeOK(w, out)
}
