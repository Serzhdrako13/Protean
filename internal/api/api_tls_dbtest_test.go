//go:build dbtest

// Integration tests against a real Postgres, mirroring
// internal/store/store_integration_test.go's harness. Bring the DB up
// first:
//
//	docker compose -f docker-compose.test.yml up -d
//	PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
//	  go test -tags dbtest ./internal/api/
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
	"protean/internal/store"
	"protean/internal/webtls"
)

func tlsTestDB(t *testing.T) *store.Store {
	t.Helper()
	url := os.Getenv("PROTEAN_TEST_DB")
	if url == "" {
		t.Skip("PROTEAN_TEST_DB not set; skipping DB integration tests")
	}
	ctx := context.Background()

	raw, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := raw.Exec(ctx, `DROP SCHEMA IF EXISTS protean CASCADE`); err != nil {
		raw.Close()
		t.Fatalf("drop schema: %v", err)
	}
	raw.Close()

	s, err := store.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Migrate(ctx, s); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func newTLSTestServer(t *testing.T, st *store.Store) *Server {
	t.Helper()
	enc, err := auth.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	s := &Server{store: st, enc: enc}
	mgr := webtls.New(st, enc)
	if err := mgr.Load(context.Background()); err != nil {
		t.Fatalf("tls bootstrap: %v", err)
	}
	s.SetTLSManager(mgr)
	return s
}

func doTLSUpdate(s *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/api/tls", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.apiTLSUpdate(rec, req)
	return rec
}

// TestTLSUpdatePreservesOtherModesSettings is the regression test for the
// real bug: TLSPage.tsx only mounts one mode's Form.Items at a time, so
// saving in one mode sends the OTHER modes' fields as Go zero values, not
// real data. Building the new state directly from the request (the old
// behavior) meant switching to self_signed to debug something wiped every
// acme_* field, and saving acme settings reset ss_sans/ss_key_algo back to
// defaults -- degrading self-signed's role as a permanent fallback that's
// generated regardless of which mode is actually active.
func TestTLSUpdatePreservesOtherModesSettings(t *testing.T) {
	st := tlsTestDB(t)
	s := newTLSTestServer(t, st)

	// 1. Configure self_signed with a custom SANs list.
	rec := doTLSUpdate(s, `{"mode":"self_signed","ss_key_algo":"rsa_2048","ss_validity_days":90,"ss_renew_before_days":10,"ss_sans":"vpn.example.com,10.0.0.5"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save self_signed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. Switch to acme -- must NOT wipe the self_signed settings just saved.
	rec = doTLSUpdate(s, `{"mode":"acme","acme_domains":"vpn.example.com","acme_email":"admin@example.com","acme_challenge":"tls-alpn-01"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save acme: status=%d body=%s", rec.Code, rec.Body.String())
	}
	state, err := st.GetTLSState(context.Background())
	if err != nil {
		t.Fatalf("GetTLSState: %v", err)
	}
	if state.SSKeyAlgo != "rsa_2048" || state.SSValidityDays != 90 || state.SSRenewBeforeDays != 10 || state.SSSans != "vpn.example.com,10.0.0.5" {
		t.Fatalf("self_signed settings were wiped by an acme save: %+v", state)
	}
	if state.AcmeDomains != "vpn.example.com" || state.AcmeEmail != "admin@example.com" {
		t.Fatalf("acme settings not applied: %+v", state)
	}

	// 3. Switch back to self_signed with DIFFERENT settings -- must NOT
	// wipe the acme settings just saved in step 2.
	rec = doTLSUpdate(s, `{"mode":"self_signed","ss_key_algo":"ecdsa_p256","ss_validity_days":397,"ss_renew_before_days":30,"ss_sans":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save self_signed again: status=%d body=%s", rec.Code, rec.Body.String())
	}
	state, err = st.GetTLSState(context.Background())
	if err != nil {
		t.Fatalf("GetTLSState: %v", err)
	}
	if state.AcmeDomains != "vpn.example.com" || state.AcmeEmail != "admin@example.com" || state.AcmeChallenge != "tls-alpn-01" {
		t.Fatalf("acme settings were wiped by a self_signed save: %+v", state)
	}
	if state.SSKeyAlgo != "ecdsa_p256" || state.SSValidityDays != 397 {
		t.Fatalf("self_signed settings not applied on the second save: %+v", state)
	}
}
