package api

import (
	"context"
	"log/slog"
	"time"
)

// StartExpiryWorker runs a loop that disables/removes peers whose expiry has
// passed. Runs until ctx is cancelled. Safe to run once per process.
func (s *Server) StartExpiryWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	s.goWorker(func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		s.sweepExpired(ctx) // run once at startup
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepExpired(ctx)
			}
		}
	})
}

func (s *Server) sweepExpired(ctx context.Context) {
	due, err := s.store.ListDuePeers(ctx)
	if err != nil {
		slog.Error("expiry sweep: list due peers", "err", err)
		return
	}
	for _, e := range due {
		if err := s.disablePeer(ctx, e.Provider, e.PeerID); err != nil {
			slog.Error("expiry: disable failed", "provider", e.Provider, "peer", e.PeerID, "err", err)
			continue // keep the expiry row; retry next sweep
		}
		if err := s.store.DeletePeerExpiry(ctx, e.Provider, e.PeerID); err != nil {
			slog.Error("expiry: clear row failed", "provider", e.Provider, "peer", e.PeerID, "err", err)
		}
		slog.Info("expiry: peer disabled", "provider", e.Provider, "peer", e.PeerID)
	}
}
