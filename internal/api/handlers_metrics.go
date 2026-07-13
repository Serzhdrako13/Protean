package api

import (
	"crypto/subtle"
	"net/http"
	"time"
)

// handleMetrics serves Prometheus text-format metrics, guarded by a bearer
// token. If METRICS_TOKEN is unset the endpoint is disabled (404) so metrics
// aren't exposed by accident. The same endpoint works for a Zabbix HTTP-agent
// item (Prometheus preprocessing) today and a Prometheus/Grafana scrape later.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsToken == "" {
		http.NotFound(w, r)
		return
	}
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(prefix) ||
		subtle.ConstantTimeCompare([]byte(authz[len(prefix):]), []byte(s.metricsToken)) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	samples := s.gatherMetrics(r.Context(), time.Now())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(renderMetrics(samples)))
}
