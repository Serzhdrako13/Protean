package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// XrayInstance is a stored Xray provider instance: the active strategy plus its
// encrypted params and optional encrypted relay spec.
type XrayInstance struct {
	Provider  string
	Strategy  string
	EncParams []byte
	EncRelay  []byte // nil = direct egress
}

func (s *Store) SaveXrayInstance(ctx context.Context, x XrayInstance) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.xray_instances (provider, strategy, enc_params, enc_relay, updated_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (provider) DO UPDATE SET
			strategy = EXCLUDED.strategy, enc_params = EXCLUDED.enc_params,
			enc_relay = EXCLUDED.enc_relay, updated_at = now()
	`, x.Provider, x.Strategy, x.EncParams, x.EncRelay)
	return err
}

func (s *Store) GetXrayInstance(ctx context.Context, provider string) (XrayInstance, error) {
	var x XrayInstance
	err := s.pool.QueryRow(ctx, `
		SELECT provider, strategy, enc_params, enc_relay
		FROM protean.xray_instances WHERE provider = $1
	`, provider).Scan(&x.Provider, &x.Strategy, &x.EncParams, &x.EncRelay)
	if errors.Is(err, pgx.ErrNoRows) {
		return XrayInstance{}, ErrNotFound
	}
	return x, err
}

func (s *Store) DeleteXrayInstance(ctx context.Context, provider string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.xray_instances WHERE provider = $1`, provider)
	return err
}

// XrayClient is one stored Xray client credential.
type XrayClient struct {
	Name    string
	EncCred []byte
}

func (s *Store) SaveXrayClient(ctx context.Context, provider, name string, encCred []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.xray_clients (provider, name, enc_cred)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, name) DO UPDATE SET enc_cred = EXCLUDED.enc_cred
	`, provider, name, encCred)
	return err
}

func (s *Store) ListXrayClients(ctx context.Context, provider string) ([]XrayClient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, enc_cred FROM protean.xray_clients WHERE provider = $1 ORDER BY name
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []XrayClient
	for rows.Next() {
		var c XrayClient
		if err := rows.Scan(&c.Name, &c.EncCred); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteXrayClient(ctx context.Context, provider, name string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.xray_clients WHERE provider = $1 AND name = $2`, provider, name)
	return err
}
