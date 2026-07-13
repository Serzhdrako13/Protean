package api

import (
	"net/http"
	"time"

	"protean/internal/store"
)

// trafficPoint is one rate sample for the history chart (bytes/sec, derived
// from the delta between two consecutive cumulative counter snapshots).
type trafficPoint struct {
	T  int64   `json:"t"` // unix seconds
	Rx float64 `json:"rx"`
	Tx float64 `json:"tx"`
}

var trafficRanges = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"3d":  72 * time.Hour,
}

// apiProviderTraffic serves the rx/tx rate history for a provider's traffic
// chart. Rates are derived at read time from raw counter snapshots
// (cumulative, like `wg show`); a negative delta means the interface/counter
// reset and is clamped to 0 rather than shown as negative.
func (s *Server) apiProviderTraffic(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	rng := trafficRanges[r.URL.Query().Get("range")]
	if rng == 0 {
		rng = time.Hour
	}
	samples, err := s.store.TrafficSamples(r.Context(), provider, time.Now().Add(-rng))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ratePoints(samples))
}

// GET /api/traffic/aggregate?range=... — same rate chart as a single
// provider's, but summed across every provider on every server (the
// "Общая нагрузка" chart on the Index page). Only counts the light "adjust
// the poll interval" version of the monitoring request; a real drag-and-drop
// per-server widget dashboard is bigger and tracked separately
// (spa-full-configurability-backlog memory).
func (s *Server) apiTrafficAggregate(w http.ResponseWriter, r *http.Request) {
	rng := trafficRanges[r.URL.Query().Get("range")]
	if rng == 0 {
		rng = time.Hour
	}
	samples, err := s.store.AggregateTrafficSamples(r.Context(), time.Now().Add(-rng))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ratePoints(samples))
}

// GET /api/servers/{id}/traffic?range=... — same rate chart, summed across
// only this server's providers (the Index page's per-server card).
func (s *Server) apiServerTrafficAggregate(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	rng := trafficRanges[r.URL.Query().Get("range")]
	if rng == 0 {
		rng = time.Hour
	}
	samples, err := s.store.AggregateTrafficSamplesByServer(r.Context(), serverID, time.Now().Add(-rng))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, ratePoints(samples))
}

// ratePoints derives bytes/sec rate points from consecutive cumulative
// counter snapshots (samples are cumulative like `wg show`); a negative
// delta means a counter reset (e.g. interface restart) and is clamped to 0
// rather than shown as negative.
func ratePoints(samples []store.TrafficSample) []trafficPoint {
	points := make([]trafficPoint, 0, len(samples))
	for i := 1; i < len(samples); i++ {
		prev, cur := samples[i-1], samples[i]
		dt := cur.TS.Sub(prev.TS).Seconds()
		if dt <= 0 {
			continue
		}
		drx := int64(cur.RxBytes) - int64(prev.RxBytes)
		dtx := int64(cur.TxBytes) - int64(prev.TxBytes)
		if drx < 0 {
			drx = 0
		}
		if dtx < 0 {
			dtx = 0
		}
		points = append(points, trafficPoint{
			T:  cur.TS.Unix(),
			Rx: float64(drx) / dt,
			Tx: float64(dtx) / dt,
		})
	}
	return points
}
