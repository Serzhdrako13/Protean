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
		INSERT INTO protean.revoked_certs (provider, serial, cn)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, serial) DO NOTHING
	`, provider, serial, cn)
	return err
}

// ListRevokedCerts returns all revocations recorded for a provider.
func (s *Store) ListRevokedCerts(ctx context.Context, provider string) ([]RevokedCertRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT serial, cn, revoked_at
		FROM protean.revoked_certs WHERE provider = $1 ORDER BY revoked_at
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
		INSERT INTO protean.crl_number (provider, number)
		VALUES ($1, 1)
		ON CONFLICT (provider) DO UPDATE SET number = protean.crl_number.number + 1
		RETURNING number
	`, provider).Scan(&n)
	return n, err
}

// ImportRevokedCerts bulk-records revocations from an adopted external CRL
// (see CA import), preserving each entry's original RevokedAt instead of
// stamping "now" -- unlike AddRevokedCert, which is for the panel's own
// live revoke-on-delete path where "now" is correct. Idempotent on
// (provider, serial), same as AddRevokedCert. All rows commit in one
// transaction: a partial import (some revocations landed, others didn't)
// is worse than none, since a missed entry means a certificate someone
// already revoked would silently work again once the panel takes over.
func (s *Store) ImportRevokedCerts(ctx context.Context, provider string, rows []RevokedCertRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, r := range rows {
		if _, err := tx.Exec(ctx, `
			INSERT INTO protean.revoked_certs (provider, serial, cn, revoked_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (provider, serial) DO NOTHING
		`, provider, r.Serial, r.CN, r.RevokedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// SeedCRLNumber ensures the stored CRL sequence number for a provider is at
// least minimum, without regressing it if the current value (or a
// concurrent revoke's NextCRLNumber call) is already higher. Used when
// importing an external CRL, so the panel's next self-issued CRL continues
// the adopted server's own sequence instead of restarting from 0/1 -- a
// lower/repeated sequence number is something some CRL-checking clients
// treat as stale and ignore.
func (s *Store) SeedCRLNumber(ctx context.Context, provider string, minimum int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.crl_number (provider, number)
		VALUES ($1, $2)
		ON CONFLICT (provider) DO UPDATE SET number = GREATEST(protean.crl_number.number, $2)
	`, provider, minimum)
	return err
}
