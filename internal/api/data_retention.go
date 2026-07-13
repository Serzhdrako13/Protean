package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"protean/internal/store"
)

type apiDataRetentionSettings struct {
	AccessRequestsEnabled bool `json:"access_requests_enabled"`
	AccessRequestsDays    int  `json:"access_requests_days"`
	AuditLogEnabled       bool `json:"audit_log_enabled"`
	AuditLogDays          int  `json:"audit_log_days"`
	LoginAttemptsEnabled  bool `json:"login_attempts_enabled"`
	LoginAttemptsDays     int  `json:"login_attempts_days"`
	LoginBansEnabled      bool `json:"login_bans_enabled"`
	LoginBansDays         int  `json:"login_bans_days"`
}

// GET /api/data-retention/settings
func (s *Server) apiDataRetentionGet(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetDataRetentionSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, apiDataRetentionSettings(t))
}

// PUT /api/data-retention/settings
func (s *Server) apiDataRetentionUpdate(w http.ResponseWriter, r *http.Request) {
	var req apiDataRetentionSettings
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, msg(r, "bad request body", "некорректное тело запроса"))
		return
	}
	for _, days := range []int{req.AccessRequestsDays, req.AuditLogDays, req.LoginAttemptsDays, req.LoginBansDays} {
		if days < 1 {
			writeErr(w, http.StatusBadRequest, msg(r, "retention period must be at least 1 day", "срок хранения должен быть не менее 1 дня"))
			return
		}
	}
	if err := s.store.SetDataRetentionSettings(r.Context(), store.DataRetentionSettings(req)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "data_retention.update", "")
	writeOK(w, nil)
}

type apiDataRetentionCleanupResult struct {
	AccessRequestsDeleted int64 `json:"access_requests_deleted"`
	AuditLogDeleted       int64 `json:"audit_log_deleted"`
	LoginAttemptsDeleted  int64 `json:"login_attempts_deleted"`
	LoginBansDeleted      int64 `json:"login_bans_deleted"`
	SessionsDeleted       int64 `json:"sessions_deleted"`
}

// POST /api/data-retention/cleanup — runs every category immediately, using
// the currently-saved retention windows regardless of each category's
// enabled toggle (clicking this button is explicit admin intent, separate
// from the scheduled auto-cleanup -- backlog item 1's "or via a special
// separate button"). Always also clears expired sessions (never
// configurable -- an expired session has zero value the instant it
// expires, this is just closing an orphaned-data gap, not a retention
// policy).
func (s *Server) apiDataRetentionCleanupNow(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.GetDataRetentionSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	result, err := s.runDataRetentionCleanup(r.Context(), settings, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "data_retention.cleanup_now", "")
	writeOK(w, result)
}

// runDataRetentionCleanup deletes eligible rows per category. force=true
// (the manual button) ignores each category's *Enabled toggle; the
// scheduled ticker passes force=false so only opted-in categories run.
func (s *Server) runDataRetentionCleanup(ctx context.Context, settings store.DataRetentionSettings, force bool) (apiDataRetentionCleanupResult, error) {
	var out apiDataRetentionCleanupResult
	now := time.Now()

	if force || settings.AccessRequestsEnabled {
		n, err := s.store.DeleteOldDeniedAccessRequests(ctx, now.Add(-time.Duration(settings.AccessRequestsDays)*24*time.Hour))
		if err != nil {
			return out, err
		}
		out.AccessRequestsDeleted = n
	}
	if force || settings.AuditLogEnabled {
		n, err := s.store.DeleteOldAuditEntries(ctx, now.Add(-time.Duration(settings.AuditLogDays)*24*time.Hour))
		if err != nil {
			return out, err
		}
		out.AuditLogDeleted = n
	}
	if force || settings.LoginAttemptsEnabled {
		n, err := s.store.DeleteOldLoginAttempts(ctx, now.Add(-time.Duration(settings.LoginAttemptsDays)*24*time.Hour))
		if err != nil {
			return out, err
		}
		out.LoginAttemptsDeleted = n
	}
	if force || settings.LoginBansEnabled {
		n, err := s.store.DeleteStaleLoginBanState(ctx, now.Add(-time.Duration(settings.LoginBansDays)*24*time.Hour))
		if err != nil {
			return out, err
		}
		out.LoginBansDeleted = n
	}
	if err := s.store.DeleteExpiredSessions(ctx); err != nil {
		return out, err
	}
	return out, nil
}

// StartDataRetentionCleanup runs the opted-in categories on an hourly tick,
// re-reading settings from the DB on every tick (unlike the fixed-at-startup
// retention passed to StartConnectionHistoryPruner/StartTrafficSampler) so
// an admin's change here takes effect without a restart. Expired sessions
// are always pruned regardless of settings -- see runDataRetentionCleanup.
func (s *Server) StartDataRetentionCleanup(ctx context.Context) {
	s.goWorker(func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				settings, err := s.store.GetDataRetentionSettings(ctx)
				if err != nil {
					slog.Error("data retention: load settings", "err", err)
					continue
				}
				if _, err := s.runDataRetentionCleanup(ctx, settings, false); err != nil {
					slog.Error("data retention: cleanup", "err", err)
				}
			}
		}
	})
}
