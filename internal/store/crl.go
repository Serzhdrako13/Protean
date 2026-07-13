package store

import (
	"context"
	"time"
)

// RevokedCertRow is one recorded certificate revocation.
type RevokedCertRow struct {
	Serial    string // decimal string of the cert serial
	CN        string
	RevokedAt time.Time
}

// AddRevokedCert records a revoked certificate. Idempotent on (provider,serial).
func (s *Store) AddRevokedCert(ctx context.Context, provider, serial, cn string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wgpanel.revoked_certs (provider, serial, cn)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, serial) DO NOTHING
	`, provider, serial, cn)
	return err
}

// ListRevokedCerts returns all revocations recorded for a provider.
func (s *Store) ListRevokedCerts(ctx context.Context, provider string) ([]RevokedCertRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT serial, cn, revoked_at
		FROM wgpanel.revoked_certs WHERE provider = $1 ORDER BY revoked_at
	`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedCertRow
	for rows.Next() {
		var r RevokedCertRow
		if err := rows.Scan(&r.Serial, &r.CN, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NextCRLNumber atomically increments and returns the CRL sequence number for
// a provider (starting at 1 on first use).
func (s *Store) NextCRLNumber(ctx context.Context, provider string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO wgpanel.crl_number (provider, number)
		VALUES ($1, 1)
		ON CONFLICT (provider) DO UPDATE SET number = wgpanel.crl_number.number + 1
		RETURNING number
	`, provider).Scan(&n)
	return n, err
}
