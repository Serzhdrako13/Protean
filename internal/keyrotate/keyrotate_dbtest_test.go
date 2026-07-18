//go:build dbtest

// Integration tests against a real Postgres. Excluded from normal builds
// (need the `dbtest` tag). Bring the DB up first:
//
//	docker compose -f docker-compose.test.yml up -d
//	PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
//	  go test -tags dbtest ./internal/keyrotate/
//
// The schema is dropped and re-migrated at the start of each run, matching
// internal/store's own dbtest convention.
package keyrotate

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
	"protean/internal/store"
)

const (
	keyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	keyC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" // never used to seed anything
)

func testDB(t *testing.T) *store.Store {
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

// seedAll writes one row into every sealed column (see sealedColumns),
// sealed with enc, and returns the plaintext it used for each so callers
// can assert against it after rotation. Two rows are seeded per table
// where the PK has more than one column, to catch a WHERE clause built
// with the wrong column order.
func seedAll(t *testing.T, ctx context.Context, s *store.Store, enc *auth.Encryptor) map[string]string {
	t.Helper()
	want := map[string]string{}
	seal := func(plaintext string) []byte {
		b, err := enc.Seal(plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return b
	}

	pt := "peer-secret-key-pem"
	if err := s.SavePeerSecret(ctx, "wg0", "pubkey-1", seal(pt)); err != nil {
		t.Fatalf("SavePeerSecret: %v", err)
	}
	want["peer_secrets.encrypted_private_key"] = pt

	pt = "ca-private-key-pem"
	if err := s.SaveCAMaterial(ctx, store.CAMaterial{
		Provider: "openvpn", CertPEM: "ca-cert", EncKeyPEM: seal(pt), Source: "internal",
	}); err != nil {
		t.Fatalf("SaveCAMaterial: %v", err)
	}
	want["ca_material.enc_key_pem"] = pt

	pt = "openvpn-client-key-pem"
	if err := s.SaveOpenVPNClient(ctx, store.OpenVPNClient{
		Provider: "openvpn", CN: "alice", CertPEM: "cert", EncKeyPEM: seal(pt),
	}); err != nil {
		t.Fatalf("SaveOpenVPNClient: %v", err)
	}
	want["openvpn_clients.enc_key_pem"] = pt

	pt = "ikev2-client-key-pem"
	if err := s.SaveIKEv2Client(ctx, store.IKEv2Client{
		Provider: "ikev2", CN: "bob", CertPEM: "cert", EncKeyPEM: seal(pt),
	}); err != nil {
		t.Fatalf("SaveIKEv2Client: %v", err)
	}
	want["ikev2_clients.enc_key_pem"] = pt

	pt = `{"webhook":"https://example/hook","token":"secret"}`
	if err := s.SaveNotifyChannel(ctx, "telegram", true, seal(pt)); err != nil {
		t.Fatalf("SaveNotifyChannel: %v", err)
	}
	want["notify_channels.config"] = pt

	pt = "server-ssh-private-key-pem"
	if err := s.CreateServer(ctx, store.Server{
		ID: "default", Label: "default", Host: "10.0.0.1", SSHUser: "protean", EncKeyPEM: seal(pt),
	}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	want["servers.enc_key_pem"] = pt

	ptParams := `{"reality_private_key":"...","short_id":"..."}`
	ptRelay := `{"host":"relay.example","port":443}`
	if err := s.SaveXrayInstance(ctx, store.XrayInstance{
		Provider: "xray", Strategy: "reality-vless-tcp", EncParams: seal(ptParams), EncRelay: seal(ptRelay),
	}); err != nil {
		t.Fatalf("SaveXrayInstance: %v", err)
	}
	want["xray_instances.enc_params"] = ptParams
	want["xray_instances.enc_relay"] = ptRelay

	pt = `{"uuid":"11111111-1111-1111-1111-111111111111"}`
	if err := s.SaveXrayClient(ctx, "xray", "client1", seal(pt)); err != nil {
		t.Fatalf("SaveXrayClient: %v", err)
	}
	want["xray_clients.enc_cred"] = pt

	pt = "manual-tls-private-key-pem"
	if err := s.SetTLSState(ctx, store.TLSState{
		Mode: "manual", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30, AcmeChallenge: "tls-alpn-01",
		ManualCertPEM: "manual-cert", ManualKeyEnc: seal(pt),
	}); err != nil {
		t.Fatalf("SetTLSState: %v", err)
	}
	want["tls_state.manual_key_enc"] = pt

	pt = "acme-account-key-bytes"
	if err := s.AcmeCachePut(ctx, "acme_account+key", seal(pt)); err != nil {
		t.Fatalf("AcmeCachePut: %v", err)
	}
	want["acme_cache.value"] = pt

	pt = "self-signed-ca-private-key-pem"
	if err := s.SaveTLSSelfSignedCA(ctx, "ca-cert-pem", seal(pt)); err != nil {
		t.Fatalf("SaveTLSSelfSignedCA: %v", err)
	}
	want["tls_self_signed.ca_key_enc"] = pt

	pt = "self-signed-leaf-private-key-pem"
	if err := s.SaveTLSSelfSignedLeaf(ctx, "leaf-cert-pem", seal(pt), time.Now(), time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("SaveTLSSelfSignedLeaf: %v", err)
	}
	want["tls_self_signed.leaf_key_enc"] = pt

	pt = "ldap-bind-password"
	if err := s.SetLDAPSettings(ctx, store.LDAPSettings{
		Enabled: true, URL: "ldap://dc.example:389", BindDN: "cn=svc", EncBindPassword: seal(pt),
		UserFilter: "(uid=%s)",
	}); err != nil {
		t.Fatalf("SetLDAPSettings: %v", err)
	}
	want["ldap_settings.enc_bind_password"] = pt

	pt = "oidc-client-secret"
	if err := s.SetOIDCSettings(ctx, store.OIDCSettings{
		Enabled: true, IssuerURL: "https://idp.example", ClientID: "protean", EncClientSecret: seal(pt),
	}); err != nil {
		t.Fatalf("SetOIDCSettings: %v", err)
	}
	want["oidc_settings.enc_client_secret"] = pt

	if len(want) != len(sealedColumns) {
		t.Fatalf("seedAll covers %d columns, sealedColumns has %d -- update seedAll to match", len(want), len(sealedColumns))
	}
	return want
}

// readAllRaw re-reads every sealed column (first row for multi-row tables)
// directly, bypassing every Store Get* method's own error handling, so the
// test observes exactly what's on disk regardless of how a given package
// treats a decrypt failure.
func readAllRaw(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, sc := range sealedColumns {
		var blob []byte
		q := "SELECT " + sc.column + " FROM protean." + sc.table + " WHERE " + sc.column + " IS NOT NULL LIMIT 1"
		if err := pool.QueryRow(ctx, q).Scan(&blob); err != nil {
			t.Fatalf("read %s.%s: %v", sc.table, sc.column, err)
		}
		out[sc.table+"."+sc.column] = blob
	}
	return out
}

func TestRotateHappyPath(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)
	encA, err := auth.NewEncryptor(keyA)
	if err != nil {
		t.Fatalf("NewEncryptor A: %v", err)
	}
	encB, err := auth.NewEncryptor(keyB)
	if err != nil {
		t.Fatalf("NewEncryptor B: %v", err)
	}

	want := seedAll(t, ctx, s, encA)

	report, err := Rotate(ctx, s.Pool(), encA, encB, false)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got := report.TotalRewritten(); got != len(want) {
		t.Errorf("TotalRewritten = %d, want %d", got, len(want))
	}
	for _, c := range report.Columns {
		if c.SkippedEmpty != 0 || c.SkippedNull != 0 {
			t.Errorf("%s.%s: unexpected skip (empty=%d null=%d)", c.Table, c.Column, c.SkippedEmpty, c.SkippedNull)
		}
	}

	raw := readAllRaw(t, ctx, s.Pool())
	for key, plaintext := range want {
		blob, ok := raw[key]
		if !ok {
			t.Errorf("%s: no row found after rotation", key)
			continue
		}
		if _, err := encA.Open(blob); err == nil {
			t.Errorf("%s: still opens with the OLD key after rotation", key)
		}
		got, err := encB.Open(blob)
		if err != nil {
			t.Errorf("%s: does not open with the new key: %v", key, err)
			continue
		}
		if got != plaintext {
			t.Errorf("%s: plaintext mismatch after rotation: got %q want %q", key, got, plaintext)
		}
	}
}

func TestRotateEmptyAndNullUntouched(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)
	encA := mustEnc(t, keyA)
	encB := mustEnc(t, keyB)

	// Seed only the columns that legitimately default to '' or NULL,
	// leaving them at their default -- ldap/oidc secrets default to ''
	// (NOT NULL DEFAULT ''), xray_instances.enc_relay/tls_state.manual_key_enc/
	// tls_self_signed.leaf_key_enc are nullable and left NULL by seeding a
	// row that doesn't set them.
	// EncBindPassword/EncClientSecret: an explicit empty (non-nil) slice --
	// the column is NOT NULL DEFAULT '', and a nil []byte would be sent as
	// SQL NULL and violate that constraint, which isn't the case this test
	// is after (it's testing the "" placeholder, not NULL).
	if err := s.SetLDAPSettings(ctx, store.LDAPSettings{Enabled: false, UserFilter: "(uid=%s)", EncBindPassword: []byte{}}); err != nil {
		t.Fatalf("SetLDAPSettings: %v", err)
	}
	if err := s.SetOIDCSettings(ctx, store.OIDCSettings{Enabled: false, EncClientSecret: []byte{}}); err != nil {
		t.Fatalf("SetOIDCSettings: %v", err)
	}
	if err := s.SaveXrayInstance(ctx, store.XrayInstance{Provider: "xray", Strategy: "s", EncParams: mustSeal(t, encA, "params")}); err != nil {
		t.Fatalf("SaveXrayInstance: %v", err)
	}
	if err := s.SaveTLSSelfSignedCA(ctx, "ca-cert", mustSeal(t, encA, "ca-key")); err != nil {
		t.Fatalf("SaveTLSSelfSignedCA: %v", err)
	}
	// tls_state row with manual_key_enc left NULL (mode != manual).
	if err := s.SetTLSState(ctx, store.TLSState{Mode: "self_signed", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30, AcmeChallenge: "tls-alpn-01"}); err != nil {
		t.Fatalf("SetTLSState: %v", err)
	}

	var beforeLDAP, beforeOIDC []byte
	if err := s.Pool().QueryRow(ctx, "SELECT enc_bind_password FROM protean.ldap_settings WHERE id=true").Scan(&beforeLDAP); err != nil {
		t.Fatalf("read ldap before: %v", err)
	}
	if err := s.Pool().QueryRow(ctx, "SELECT enc_client_secret FROM protean.oidc_settings WHERE id=true").Scan(&beforeOIDC); err != nil {
		t.Fatalf("read oidc before: %v", err)
	}
	if len(beforeLDAP) != 0 || len(beforeOIDC) != 0 {
		t.Fatalf("test setup bug: expected empty placeholders, got ldap=%d oidc=%d bytes", len(beforeLDAP), len(beforeOIDC))
	}

	report, err := Rotate(ctx, s.Pool(), encA, encB, false)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	var afterLDAP, afterOIDC []byte
	var relay, manualKey, leafKey *[]byte
	if err := s.Pool().QueryRow(ctx, "SELECT enc_bind_password FROM protean.ldap_settings WHERE id=true").Scan(&afterLDAP); err != nil {
		t.Fatalf("read ldap after: %v", err)
	}
	if err := s.Pool().QueryRow(ctx, "SELECT enc_client_secret FROM protean.oidc_settings WHERE id=true").Scan(&afterOIDC); err != nil {
		t.Fatalf("read oidc after: %v", err)
	}
	if len(afterLDAP) != 0 {
		t.Errorf("ldap_settings.enc_bind_password: expected to stay empty, got %d bytes", len(afterLDAP))
	}
	if len(afterOIDC) != 0 {
		t.Errorf("oidc_settings.enc_client_secret: expected to stay empty, got %d bytes", len(afterOIDC))
	}
	if err := s.Pool().QueryRow(ctx, "SELECT enc_relay FROM protean.xray_instances WHERE provider='xray'").Scan(&relay); err != nil {
		t.Fatalf("read enc_relay: %v", err)
	}
	if relay != nil {
		t.Errorf("xray_instances.enc_relay: expected to stay NULL, got a value")
	}
	if err := s.Pool().QueryRow(ctx, "SELECT manual_key_enc FROM protean.tls_state WHERE id=true").Scan(&manualKey); err != nil {
		t.Fatalf("read manual_key_enc: %v", err)
	}
	if manualKey != nil {
		t.Errorf("tls_state.manual_key_enc: expected to stay NULL, got a value")
	}
	if err := s.Pool().QueryRow(ctx, "SELECT leaf_key_enc FROM protean.tls_self_signed WHERE id=true").Scan(&leafKey); err != nil {
		t.Fatalf("read leaf_key_enc: %v", err)
	}
	if leafKey != nil {
		t.Errorf("tls_self_signed.leaf_key_enc: expected to stay NULL, got a value")
	}

	// Sanity: the one real secret we DID seed (enc_params/ca_key_enc) was
	// still genuinely rotated in the same run.
	found := map[string]bool{}
	for _, c := range report.Columns {
		if c.Rewritten > 0 {
			found[c.Table+"."+c.Column] = true
		}
	}
	if !found["xray_instances.enc_params"] || !found["tls_self_signed.ca_key_enc"] {
		t.Errorf("expected the real (non-empty) secrets seeded in this test to be rewritten, report=%+v", report)
	}
}

func TestRotateWrongOldKeyAborts(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)
	encA := mustEnc(t, keyA)
	encC := mustEnc(t, keyC) // wrong "old" key -- never used to seed
	encB := mustEnc(t, keyB)

	want := seedAll(t, ctx, s, encA)

	if _, err := Rotate(ctx, s.Pool(), encC, encB, false); err == nil {
		t.Fatal("Rotate with the wrong old key should have failed, got nil error")
	}

	raw := readAllRaw(t, ctx, s.Pool())
	for key, plaintext := range want {
		blob := raw[key]
		got, err := encA.Open(blob)
		if err != nil {
			t.Errorf("%s: no longer opens with the ORIGINAL key after an aborted rotation: %v", key, err)
			continue
		}
		if got != plaintext {
			t.Errorf("%s: plaintext changed after an aborted rotation", key)
		}
	}
}

func TestRotateDryRun(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)
	encA := mustEnc(t, keyA)
	encB := mustEnc(t, keyB)

	want := seedAll(t, ctx, s, encA)

	report, err := Rotate(ctx, s.Pool(), encA, encB, true)
	if err != nil {
		t.Fatalf("Rotate (dry run): %v", err)
	}
	if got := report.TotalRewritten(); got != len(want) {
		t.Errorf("dry-run TotalRewritten = %d, want %d (dry run should still report accurate counts)", got, len(want))
	}

	raw := readAllRaw(t, ctx, s.Pool())
	for key, plaintext := range want {
		blob := raw[key]
		got, err := encA.Open(blob)
		if err != nil {
			t.Errorf("%s: no longer opens with the old key after a DRY RUN (should be untouched): %v", key, err)
			continue
		}
		if got != plaintext {
			t.Errorf("%s: plaintext changed after a dry run", key)
		}
		if _, err := encB.Open(blob); err == nil {
			t.Errorf("%s: opens with the new key after a DRY RUN -- it should not have been committed", key)
		}
	}
}

func TestDetect(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)
	encA := mustEnc(t, keyA)
	encB := mustEnc(t, keyB)
	encC := mustEnc(t, keyC)

	seedAll(t, ctx, s, encA)

	before, err := Detect(ctx, s.Pool(), encA)
	if err != nil {
		t.Fatalf("Detect(A) before rotation: %v", err)
	}
	for col, ok := range before {
		if !ok {
			t.Errorf("Detect(A) before rotation: %s reported false, want true", col)
		}
	}

	if _, err := Rotate(ctx, s.Pool(), encA, encB, false); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	afterA, err := Detect(ctx, s.Pool(), encA)
	if err != nil {
		t.Fatalf("Detect(A) after rotation: %v", err)
	}
	for col, ok := range afterA {
		if ok {
			t.Errorf("Detect(A) after rotation: %s still reports true, want false (rotated away from A)", col)
		}
	}

	afterB, err := Detect(ctx, s.Pool(), encB)
	if err != nil {
		t.Fatalf("Detect(B) after rotation: %v", err)
	}
	for col, ok := range afterB {
		if !ok {
			t.Errorf("Detect(B) after rotation: %s reports false, want true", col)
		}
	}

	unrelated, err := Detect(ctx, s.Pool(), encC)
	if err != nil {
		t.Fatalf("Detect(C): %v", err)
	}
	for col, ok := range unrelated {
		if ok {
			t.Errorf("Detect(C) (a key never used): %s reports true, want false", col)
		}
	}
}

// TestSealedColumnsMatchSchema guards against a future sealed secret
// silently escaping rotation: every bytea column in the schema must be
// registered in sealedColumns.
func TestSealedColumnsMatchSchema(t *testing.T) {
	ctx := context.Background()
	s := testDB(t)

	rows, err := s.Pool().Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'protean' AND udt_name = 'bytea'
	`)
	if err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	defer rows.Close()

	registered := map[string]bool{}
	for _, sc := range sealedColumns {
		registered[sc.table+"."+sc.column] = true
	}

	var found int
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatalf("scan: %v", err)
		}
		found++
		if !registered[table+"."+column] {
			t.Errorf("schema has bytea column %s.%s not registered in keyrotate.sealedColumns -- add it there or this column's secret won't survive a key rotation", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if found != len(sealedColumns) {
		t.Errorf("schema has %d bytea columns, sealedColumns registers %d -- investigate the mismatch (extra or stale entries)", found, len(sealedColumns))
	}
}

func mustEnc(t *testing.T, keyHex string) *auth.Encryptor {
	t.Helper()
	enc, err := auth.NewEncryptor(keyHex)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return enc
}

func mustSeal(t *testing.T, enc *auth.Encryptor, plaintext string) []byte {
	t.Helper()
	b, err := enc.Seal(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return b
}
