package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// TLSState is the panel's own web-listener TLS configuration -- a
// singleton, unlike per-provider settings (see migration 0025 for the mode
// semantics).
type TLSState struct {
	Mode string

	SSKeyAlgo         string
	SSValidityDays    int
	SSRenewBeforeDays int
	SSSans            string // comma-separated hostnames/IPs

	AcmeDirectoryURL string
	AcmeDomains      string
	AcmeEmail        string
	AcmeChallenge    string
	AcmeTrustRootPEM string

	ManualCertPEM string
	ManualKeyEnc  []byte
}

// defaultTLSState is what a fresh install gets before any row exists --
// self-signed, sane defaults, so the panel is never plain-HTTP even before
// an admin has logged in to configure anything.
func defaultTLSState() TLSState {
	return TLSState{
		Mode:      "self_signed",
		SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30,
		AcmeChallenge: "tls-alpn-01",
	}
}

// GetTLSState returns the current TLS settings, defaulting (not erroring)
// when no row exists yet -- mirrors GetProviderSettings' "absent row means
// defaults" convention.
func (s *Store) GetTLSState(ctx context.Context) (TLSState, error) {
	t := defaultTLSState()
	err := s.pool.QueryRow(ctx, `
		SELECT mode, ss_key_algo, ss_validity_days, ss_renew_before_days, ss_sans,
		       acme_directory_url, acme_domains, acme_email, acme_challenge, acme_trust_root_pem,
		       manual_cert_pem, manual_key_enc
		FROM protean.tls_state WHERE id = true
	`).Scan(
		&t.Mode, &t.SSKeyAlgo, &t.SSValidityDays, &t.SSRenewBeforeDays, &t.SSSans,
		&t.AcmeDirectoryURL, &t.AcmeDomains, &t.AcmeEmail, &t.AcmeChallenge, &t.AcmeTrustRootPEM,
		&t.ManualCertPEM, &t.ManualKeyEnc,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, nil
	}
	if err != nil {
		return TLSState{}, err
	}
	return t, nil
}

// SetTLSState upserts the singleton row.
func (s *Store) SetTLSState(ctx context.Context, t TLSState) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.tls_state (
			id, mode, ss_key_algo, ss_validity_days, ss_renew_before_days, ss_sans,
			acme_directory_url, acme_domains, acme_email, acme_challenge, acme_trust_root_pem,
			manual_cert_pem, manual_key_enc, updated_at
		) VALUES (true, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
		ON CONFLICT (id) DO UPDATE SET
			mode = EXCLUDED.mode,
			ss_key_algo = EXCLUDED.ss_key_algo,
			ss_validity_days = EXCLUDED.ss_validity_days,
			ss_renew_before_days = EXCLUDED.ss_renew_before_days,
			ss_sans = EXCLUDED.ss_sans,
			acme_directory_url = EXCLUDED.acme_directory_url,
			acme_domains = EXCLUDED.acme_domains,
			acme_email = EXCLUDED.acme_email,
			acme_challenge = EXCLUDED.acme_challenge,
			acme_trust_root_pem = EXCLUDED.acme_trust_root_pem,
			manual_cert_pem = EXCLUDED.manual_cert_pem,
			manual_key_enc = EXCLUDED.manual_key_enc,
			updated_at = now()
	`, t.Mode, t.SSKeyAlgo, t.SSValidityDays, t.SSRenewBeforeDays, t.SSSans,
		t.AcmeDirectoryURL, t.AcmeDomains, t.AcmeEmail, t.AcmeChallenge, t.AcmeTrustRootPEM,
		t.ManualCertPEM, t.ManualKeyEnc)
	return err
}

// TLSSelfSigned is the panel's permanent self-signed CA + its currently
// issued leaf cert -- kept separate from TLSState so switching modes back
// and forth never discards or regenerates the CA (a stable fallback
// identity matters more than a fresh one each time).
type TLSSelfSigned struct {
	CACertPEM   string
	CAKeyEnc    []byte
	LeafCertPEM string
	LeafKeyEnc  []byte
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// GetTLSSelfSigned returns (state, found, error) -- found=false means no CA
// has been generated yet (first boot).
func (s *Store) GetTLSSelfSigned(ctx context.Context) (TLSSelfSigned, bool, error) {
	var t TLSSelfSigned
	var issuedAt, expiresAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT ca_cert_pem, ca_key_enc, leaf_cert_pem, leaf_key_enc, issued_at, expires_at
		FROM protean.tls_self_signed WHERE id = true
	`).Scan(&t.CACertPEM, &t.CAKeyEnc, &t.LeafCertPEM, &t.LeafKeyEnc, &issuedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TLSSelfSigned{}, false, nil
	}
	if err != nil {
		return TLSSelfSigned{}, false, err
	}
	if issuedAt != nil {
		t.IssuedAt = *issuedAt
	}
	if expiresAt != nil {
		t.ExpiresAt = *expiresAt
	}
	return t, true, nil
}

// SaveTLSSelfSignedCA persists a freshly-generated CA (first boot only --
// callers should check GetTLSSelfSigned's found=false first, since this
// always creates/replaces the whole row including any existing leaf).
func (s *Store) SaveTLSSelfSignedCA(ctx context.Context, caCertPEM string, caKeyEnc []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.tls_self_signed (id, ca_cert_pem, ca_key_enc)
		VALUES (true, $1, $2)
		ON CONFLICT (id) DO UPDATE SET ca_cert_pem = EXCLUDED.ca_cert_pem, ca_key_enc = EXCLUDED.ca_key_enc
	`, caCertPEM, caKeyEnc)
	return err
}

// SaveTLSSelfSignedLeaf updates just the leaf cert (re-issued periodically
// by the auto-renew worker) without touching the CA.
func (s *Store) SaveTLSSelfSignedLeaf(ctx context.Context, leafCertPEM string, leafKeyEnc []byte, issuedAt, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE protean.tls_self_signed
		SET leaf_cert_pem = $1, leaf_key_enc = $2, issued_at = $3, expires_at = $4
		WHERE id = true
	`, leafCertPEM, leafKeyEnc, issuedAt, expiresAt)
	return err
}

// AcmeCacheGet/Put/Delete back a golang.org/x/crypto/acme/autocert.Cache
// implementation (see internal/webtls) -- values are opaque, sealed blobs;
// this layer just stores/retrieves bytes, same division of concerns as
// every other secret column in this package.
func (s *Store) AcmeCacheGet(ctx context.Context, key string) ([]byte, bool, error) {
	var data []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM protean.acme_cache WHERE key = $1`, key).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (s *Store) AcmeCachePut(ctx context.Context, key string, data []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.acme_cache (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, key, data)
	return err
}

func (s *Store) AcmeCacheDelete(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.acme_cache WHERE key = $1`, key)
	return err
}
