package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// SetPeerDetectionDismissed records that an admin reviewed this peer
// during network-structure detection (internal/api/network_detect.go)
// and explicitly declined to turn it into equipment -- idempotent, so
// dismissing an already-dismissed peer just refreshes the timestamp.
func (s *Store) SetPeerDetectionDismissed(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.peer_detection_dismissed (provider, peer_key)
		VALUES ($1, $2)
		ON CONFLICT (provider, peer_key) DO UPDATE SET dismissed_at = now()
	`, provider, peerKey)
	return err
}

// IsPeerDetectionDismissed reports whether a peer was previously declined.
func (s *Store) IsPeerDetectionDismissed(ctx context.Context, provider, peerKey string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT true FROM protean.peer_detection_dismissed WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists, nil
}

// ClearPeerDetectionDismissed un-dismisses a peer -- lets an admin force
// it back into the next detection preview instead of it staying hidden
// under "already reviewed" forever.
func (s *Store) ClearPeerDetectionDismissed(ctx context.Context, provider, peerKey string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM protean.peer_detection_dismissed WHERE provider = $1 AND peer_key = $2
	`, provider, peerKey)
	return err
}

// DismissedPeerKeys returns every peer_key dismissed for one provider, as
// a set -- convenient for detectNetworkStructure to check membership in
// one query instead of one row-by-row lookup per peer.
func (s *Store) DismissedPeerKeys(ctx context.Context, provider string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT peer_key FROM protean.peer_detection_dismissed WHERE provider = $1
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}
