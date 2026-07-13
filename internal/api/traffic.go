package api

import (
	"context"
	"log/slog"
	"time"
)

// StartTrafficSampler periodically snapshots each provider's rx/tx counters
// into the traffic_samples table (for the history chart) and prunes rows
// older than retention on an hourly tick. interval <= 0 disables sampling
// entirely (no rows written, no disk used).
func (s *Server) StartTrafficSampler(ctx context.Context, interval, retention time.Duration) {
	if interval <= 0 {
		return
	}
	s.goWorker(func() {
		sample := time.NewTicker(interval)
		defer sample.Stop()
		prune := time.NewTicker(time.Hour)
		defer prune.Stop()
		s.sampleTraffic(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sample.C:
				s.sampleTraffic(ctx)
			case <-prune.C:
				s.pruneTraffic(ctx, retention)
			}
		}
	})
}

func (s *Server) sampleTraffic(ctx context.Context) {
	if s.store == nil {
		return
	}
	now := time.Now()
	for _, prov := range s.reg.List() {
		st, err := s.providerStatus(ctx, prov)
		if err != nil || !st.Up {
			continue
		}
		if err := s.store.InsertTrafficSample(ctx, prov.Name(), now, st.TotalRxBytes, st.TotalTxBytes); err != nil {
			slog.Error("traffic sample: insert", "provider", prov.Name(), "err", err)
		}
	}
}

func (s *Server) pruneTraffic(ctx context.Context, retention time.Duration) {
	if s.store == nil || retention <= 0 {
		return
	}
	if err := s.store.PruneTrafficSamples(ctx, time.Now().Add(-retention)); err != nil {
		slog.Error("traffic prune", "err", err)
	}
}
