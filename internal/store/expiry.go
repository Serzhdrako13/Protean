package store

import (
	"context"
	"time"
)

// PeerExpiry pairs a peer with its expiry instant.
type PeerExpiry struct {
	Provider  string
	PeerID    string
	ExpiresAt time.Time
}

func (s *Store) SetPeerExpiry(ctx context.Context, provider, peerID string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.peer_expiry (provider, peer_id, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, peer_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`, provider, peerID, expiresAt)
	return err
}

func (s *Store) DeletePeerExpiry(ctx context.Context, provider, peerID string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM wgpanel.peer_expiry WHERE provider = $1 AND peer_id = $2
	`, provider, peerID)
	return err
}

// ExpiryForProvider returns peer_id -> expires_at for one provider instance.
func (s *Store) ExpiryForProvider(ctx context.Context, provider string) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT peer_id, expires_at FROM wgpanel.peer_expiry WHERE provider = $1
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var exp time.Time
		if err := rows.Scan(&id, &exp); err != nil {
			return nil, err
		}
		out[id] = exp
	}
	return out, rows.Err()
}

// ListDuePeers returns peers whose expiry has passed.
func (s *Store) ListDuePeers(ctx context.Context) ([]PeerExpiry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, peer_id, expires_at FROM wgpanel.peer_expiry
		WHERE expires_at <= now()
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerExpiry
	for rows.Next() {
		var e PeerExpiry
		if err := rows.Scan(&e.Provider, &e.PeerID, &e.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
