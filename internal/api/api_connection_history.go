package api

import (
	"net/http"
	"strconv"
	"time"

	"protean/internal/store"
)

type apiConnectionEvent struct {
	TS       time.Time `json:"ts"`
	Provider string    `json:"provider"`
	PeerID   string    `json:"peer_id"`
	PeerName string    `json:"peer_name"`
	Event    string    `json:"event"`
}

// GET /api/connection-history?provider=&peer_id=&since_hours=&limit=
func (s *Server) apiConnectionHistoryList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sinceHours, _ := strconv.Atoi(q.Get("since_hours"))
	if sinceHours <= 0 {
		sinceHours = 24
	}
	limit, _ := strconv.Atoi(q.Get("limit"))

	rows, err := s.store.ListConnectionHistory(r.Context(), store.ConnectionHistoryFilter{
		Provider: q.Get("provider"),
		PeerID:   q.Get("peer_id"),
		Since:    time.Now().Add(-time.Duration(sinceHours) * time.Hour),
		Limit:    limit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiConnectionEvent, 0, len(rows))
	for _, row := range rows {
		out = append(out, apiConnectionEvent(row))
	}
	writeOK(w, out)
}
