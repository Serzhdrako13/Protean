package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type IKEv2Client struct {
	Provider    string
	CN          string
	CertPEM     string
	EncKeyPEM   []byte
	P12Password string
	Address     string
	Subnets     string
	CreatedAt   time.Time
}

func (s *Store) SaveIKEv2Client(ctx context.Context, c IKEv2Client) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.ikev2_clients (provider, cn, cert_pem, enc_key_pem, p12_password, address, subnets)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (provider, cn) DO UPDATE SET
			cert_pem = EXCLUDED.cert_pem, enc_key_pem = EXCLUDED.enc_key_pem,
			p12_password = EXCLUDED.p12_password, address = EXCLUDED.address, subnets = EXCLUDED.subnets
	`, c.Provider, c.CN, c.CertPEM, c.EncKeyPEM, c.P12Password, c.Address, c.Subnets)
	return err
}

func (s *Store) GetIKEv2Client(ctx context.Context, provider, cn string) (IKEv2Client, error) {
	var c IKEv2Client
	err := s.pool.QueryRow(ctx, `
		SELECT provider, cn, cert_pem, enc_key_pem, p12_password, address, subnets, created_at
		FROM protean.ikev2_clients WHERE provider = $1 AND cn = $2
	`, provider, cn).Scan(&c.Provider, &c.CN, &c.CertPEM, &c.EncKeyPEM, &c.P12Password, &c.Address, &c.Subnets, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IKEv2Client{}, ErrNotFound
	}
	return c, err
}

func (s *Store) ListIKEv2Clients(ctx context.Context, provider string) ([]IKEv2Client, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT provider, cn, cert_pem, enc_key_pem, p12_password, address, subnets, created_at
		FROM protean.ikev2_clients WHERE provider = $1 ORDER BY cn
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IKEv2Client
	for rows.Next() {
		var c IKEv2Client
		if err := rows.Scan(&c.Provider, &c.CN, &c.CertPEM, &c.EncKeyPEM, &c.P12Password, &c.Address, &c.Subnets, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteIKEv2Client(ctx context.Context, provider, cn string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.ikev2_clients WHERE provider = $1 AND cn = $2`, provider, cn)
	return err
}

// SaveCertServerRoutes records the push-routes/egress last applied to a
// cert-based server so the provider can regenerate its config autonomously.
func (s *Store) SaveCertServerRoutes(ctx context.Context, provider string, pushRoutes []string, egress bool) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.cert_server_routes (provider, push_routes, egress, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (provider) DO UPDATE SET
			push_routes = EXCLUDED.push_routes, egress = EXCLUDED.egress, updated_at = now()
	`, provider, joinCSV(pushRoutes), egress)
	return err
}

// GetCertServerRoutes returns the persisted routes/egress; ok is false when the
// server has not been provisioned yet.
func (s *Store) GetCertServerRoutes(ctx context.Context, provider string) (pushRoutes []string, egress bool, ok bool, err error) {
	var csv string
	err = s.pool.QueryRow(ctx, `
		SELECT push_routes, egress FROM protean.cert_server_routes WHERE provider = $1
	`, provider).Scan(&csv, &egress)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	return splitCSV(csv), egress, true, nil
}

func joinCSV(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
