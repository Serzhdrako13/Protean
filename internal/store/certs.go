package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// CAMaterial is a provider's CA certificate and (encrypted) key.
type CAMaterial struct {
	Provider  string
	CertPEM   string
	EncKeyPEM []byte
	Source    string // internal | external
	CreatedAt time.Time
}

func (s *Store) GetCAMaterial(ctx context.Context, provider string) (CAMaterial, error) {
	var m CAMaterial
	err := s.pool.QueryRow(ctx, `
		SELECT provider, cert_pem, enc_key_pem, source, created_at
		FROM wgpanel.ca_material WHERE provider = $1
	`, provider).Scan(&m.Provider, &m.CertPEM, &m.EncKeyPEM, &m.Source, &m.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CAMaterial{}, ErrNotFound
	}
	return m, err
}

func (s *Store) SaveCAMaterial(ctx context.Context, m CAMaterial) error {
	if m.Source == "" {
		m.Source = "internal"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.ca_material (provider, cert_pem, enc_key_pem, source)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider) DO UPDATE SET
			cert_pem = EXCLUDED.cert_pem, enc_key_pem = EXCLUDED.enc_key_pem, source = EXCLUDED.source
	`, m.Provider, m.CertPEM, m.EncKeyPEM, m.Source)
	return err
}

// OpenVPNClient is a stored OpenVPN client (cert + encrypted key + routing),
// scoped to a provider instance (server/instance key).
type OpenVPNClient struct {
	Provider  string
	CN        string
	CertPEM   string
	EncKeyPEM []byte
	Address   string
	Subnets   string // comma-separated
	CreatedAt time.Time
}

func (s *Store) SaveOpenVPNClient(ctx context.Context, c OpenVPNClient) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.openvpn_clients (provider, cn, cert_pem, enc_key_pem, address, subnets)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (provider, cn) DO UPDATE SET
			cert_pem = EXCLUDED.cert_pem, enc_key_pem = EXCLUDED.enc_key_pem,
			address = EXCLUDED.address, subnets = EXCLUDED.subnets
	`, c.Provider, c.CN, c.CertPEM, c.EncKeyPEM, c.Address, c.Subnets)
	return err
}

func (s *Store) GetOpenVPNClient(ctx context.Context, provider, cn string) (OpenVPNClient, error) {
	var c OpenVPNClient
	err := s.pool.QueryRow(ctx, `
		SELECT provider, cn, cert_pem, enc_key_pem, address, subnets, created_at
		FROM wgpanel.openvpn_clients WHERE provider = $1 AND cn = $2
	`, provider, cn).Scan(&c.Provider, &c.CN, &c.CertPEM, &c.EncKeyPEM, &c.Address, &c.Subnets, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OpenVPNClient{}, ErrNotFound
	}
	return c, err
}

func (s *Store) ListOpenVPNClients(ctx context.Context, provider string) ([]OpenVPNClient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, cn, cert_pem, enc_key_pem, address, subnets, created_at
		FROM wgpanel.openvpn_clients WHERE provider = $1 ORDER BY cn
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OpenVPNClient
	for rows.Next() {
		var c OpenVPNClient
		if err := rows.Scan(&c.Provider, &c.CN, &c.CertPEM, &c.EncKeyPEM, &c.Address, &c.Subnets, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteOpenVPNClient(ctx context.Context, provider, cn string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM wgpanel.openvpn_clients WHERE provider = $1 AND cn = $2`, provider, cn)
	return err
}
