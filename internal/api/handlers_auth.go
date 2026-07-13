package api

import (
	"net/http"
	"os"
)

// licensePaths: the Docker image copies the repo's LICENSE to /LICENSE
// (see Dockerfile) since the image itself is a distributed copy of the
// software and Elastic License 2.0 requires the terms to travel with any
// copy -- the git repo's LICENSE file alone doesn't reach someone who
// only pulls the image. Falls back to the source tree for local
// `go run`/`go build` from a checkout, where /LICENSE doesn't exist.
var licensePaths = []string{"/LICENSE", "LICENSE"}

// handleLicense serves the plain-text license -- unauthenticated, same as
// a terms-of-service page.
func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	for _, p := range licensePaths {
		if b, err := os.ReadFile(p); err == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(b)
			return
		}
	}
	http.Error(w, "license file not found", http.StatusNotFound)
}

// handleHealthz is an unauthenticated liveness/readiness probe. The DB is
// required (503 if unreachable -- the panel can't function). The managed host's
// SSH reachability is reported too, but a host outage does NOT fail the probe
// (that would kill the container over a remote issue): it returns 200 with a
// "host degraded" note so monitoring can see it without restarting the panel.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		http.Error(w, "db unreachable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if ok, msg := s.hostHealthy(r.Context()); !ok {
		_, _ = w.Write([]byte("ok (host degraded: " + msg + ")"))
		return
	}
	_, _ = w.Write([]byte("ok"))
}
