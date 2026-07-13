package api

import (
	"context"
	"log/slog"

	"protean/internal/vpn"
)

// ReconcileState runs a one-shot startup check that compares the panel's
// database against the live state on the host and logs divergences. It does
// NOT auto-repair: a crash between a provider write and its DB write (or vice
// versa) can leave, e.g., a stored private key for a peer that no longer exists
// on the interface, or a live peer the panel has no key for. Surfacing these in
// the log lets the operator act; silent auto-deletion could destroy the wrong
// side. Runs in the background so it never blocks startup.
func (s *Server) ReconcileState(ctx context.Context) {
	if s.store == nil {
		return
	}
	s.goWorker(func() {
		for _, prov := range s.reg.List() {
			if ctx.Err() != nil {
				return
			}
			// Only wg-family keeps per-peer private keys in peer_secrets;
			// cert providers derive everything from their own tables.
			if _, cert := prov.(vpn.ClientConfigProvider); cert {
				continue
			}
			s.reconcileProvider(ctx, prov)
		}
	})
}

func (s *Server) reconcileProvider(ctx context.Context, prov vpn.Provider) {
	name := prov.Name()

	status, err := prov.Status(ctx)
	if err != nil || !status.Up {
		return // host/interface unavailable; nothing reliable to compare
	}

	peers, err := prov.ListPeers(ctx)
	if err != nil {
		slog.Warn("reconcile: list peers failed; skipping", "provider", name, "err", err)
		return
	}
	live := make(map[string]bool, len(peers))
	for _, p := range peers {
		live[p.PublicKey] = true
	}

	secretKeys, err := s.store.ListPeerSecretKeys(ctx, name)
	if err != nil {
		slog.Warn("reconcile: list secrets failed; skipping", "provider", name, "err", err)
		return
	}
	stored := make(map[string]bool, len(secretKeys))
	for _, k := range secretKeys {
		stored[k] = true
	}

	// Orphan secrets: a stored private key with no matching live peer (e.g. a
	// delete that removed the peer but crashed before clearing the secret).
	orphans := 0
	for _, k := range secretKeys {
		if !live[k] {
			orphans++
			slog.Warn("reconcile: stored key for a peer not present on the interface (orphan secret)",
				"provider", name, "public_key", k)
		}
	}

	// Live peers the panel has no key for. Legitimate for client-keygen
	// (self-managed) peers, so this is informational, not an error.
	unmanaged := 0
	for _, p := range peers {
		if !stored[p.PublicKey] {
			unmanaged++
		}
	}
	if orphans > 0 || unmanaged > 0 {
		slog.Info("reconcile: state summary",
			"provider", name, "live_peers", len(peers), "stored_keys", len(secretKeys),
			"orphan_secrets", orphans, "peers_without_stored_key", unmanaged)
	}
}
