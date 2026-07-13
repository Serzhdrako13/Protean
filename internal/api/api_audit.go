package api

import (
	"net/http"
	"time"
)

type apiAuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
}

// GET /api/audit
func (s *Server) apiAuditList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAuditEntries(r.Context(), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiAuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, apiAuditEntry{Timestamp: e.Timestamp, Username: e.Username, Action: e.Action, Target: e.Target})
	}
	writeOK(w, out)
}
