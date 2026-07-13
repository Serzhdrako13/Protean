package api

import (
	"context"
	"log/slog"
	"time"
)

// StartConnectionHistoryPruner periodically deletes connection_history rows
// older than retention (an hourly tick, same cadence as StartTrafficSampler's
// pruning) -- the events themselves are written inline from
// notify.go's watchTick as they're detected, not on a tick of their own.
// retention <= 0 keeps history forever (no pruning).
func (s *Server) StartConnectionHistoryPruner(ctx context.Context, retention time.Duration) {
	if retention <= 0 {
		return
	}
	s.goWorker(func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.store.PruneConnectionHistory(ctx, time.Now().Add(-retention)); err != nil {
					slog.Error("connection history prune", "err", err)
				}
			}
		}
	})
}
