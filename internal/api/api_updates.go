package api

import (
	"errors"
	"net/http"

	"protean/internal/console"
	"protean/internal/store"
)

// GET /api/servers/{id}/updates -- pending OS package updates, read-only.
func (s *Server) apiServerUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.installerFor == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "installer not configured", "установщик не настроен"))
		return
	}
	inst, ok := s.installerFor(id)
	if !ok {
		writeErr(w, http.StatusNotFound, msg(r, "server not reachable", "сервер недоступен"))
		return
	}
	info, err := inst.CheckUpdates(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeOK(w, info)
}

// POST /api/servers/{id}/updates/apply -- mints a ticket authorizing a
// streamed run of `updates-apply` over GET /api/console/updates-ws, the
// same ticket/bridge machinery the web SSH console uses (see
// serveConsoleBridge). Applying updates can take minutes and the operator
// wants to watch it happen, not just get a pass/fail after the fact.
func (s *Server) apiServerUpdatesApply(w http.ResponseWriter, r *http.Request) {
	if s.console == nil {
		writeErr(w, http.StatusServiceUnavailable, msg(r, "console not configured", "консоль не настроена"))
		return
	}
	id := r.PathValue("id")
	srv, err := s.store.GetServer(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, msg(r, "server not found", "сервер не найден"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !srv.Enabled && !srv.PanelHost {
		writeErr(w, http.StatusForbidden, msg(r, "server is disabled", "сервер отключён"))
		return
	}

	username := usernameFromContext(r.Context())
	ticket, err := s.console.Mint(username, id)
	if err != nil {
		if errors.Is(err, console.ErrTooManySessions) {
			writeErr(w, http.StatusTooManyRequests, msg(r, "too many concurrent console sessions", "слишком много одновременных сессий консоли"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r.Context(), "updates.apply.start", id)
	writeOK(w, apiConsoleSessionResp{
		Ticket:      ticket,
		WSURL:       "/api/console/updates-ws?ticket=" + ticket,
		TargetLabel: srv.Label,
	})
}
