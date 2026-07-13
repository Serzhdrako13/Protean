package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type DisabledPeer struct {
	Provider   string
	PublicKey  string
	Name       string
	AllowedIPs string // comma-separated
	Keepalive  int
	DisabledAt time.Time
}

func (s *Store) SaveDisabledPeer(ctx context.Context, p DisabledPeer) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.disabled_peers (provider, public_key, name, allowed_ips, keepalive)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (provider, public_key) DO UPDATE SET
			name = EXCLUDED.name, allowed_ips = EXCLUDED.allowed_ips, keepalive = EXCLUDED.keepalive
	`, p.Provider, p.PublicKey, p.Name, p.AllowedIPs, p.Keepalive)
	return err
}

func (s *Store) GetDisabledPeer(ctx context.Context, provider, publicKey string) (DisabledPeer, error) {
	var p DisabledPeer
	err := s.pool.QueryRow(ctx, `
		SELECT provider, public_key, name, allowed_ips, keepalive, disabled_at
		FROM wgpanel.disabled_peers WHERE provider = $1 AND public_key = $2
	`, provider, publicKey).Scan(&p.Provider, &p.PublicKey, &p.Name, &p.AllowedIPs, &p.Keepalive, &p.DisabledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DisabledPeer{}, ErrNotFound
	}
	return p, err
}

func (s *Store) ListDisabledPeers(ctx context.Context, provider string) ([]DisabledPeer, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, public_key, name, allowed_ips, keepalive, disabled_at
		FROM wgpanel.disabled_peers WHERE provider = $1 ORDER BY name
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DisabledPeer
	for rows.Next() {
		var p DisabledPeer
		if err := rows.Scan(&p.Provider, &p.PublicKey, &p.Name, &p.AllowedIPs, &p.Keepalive, &p.DisabledAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteDisabledPeer(ctx context.Context, provider, publicKey string) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM wgpanel.disabled_peers WHERE provider = $1 AND public_key = $2
	`, provider, publicKey)
	return err
}
