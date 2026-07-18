//go:build dbtest

// Integration tests against a real Postgres. Excluded from normal builds (need
// the `dbtest` tag). Bring the DB up first:
//
//	docker compose -f docker-compose.test.yml up -d
//	PROTEAN_TEST_DB='postgres://protean:protean@localhost:5433/protean?sslmode=disable' \
//	  go test -tags dbtest ./internal/store/
//
// The schema is dropped and re-migrated at the start of each run.
package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testDB(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("PROTEAN_TEST_DB")
	if url == "" {
		t.Skip("PROTEAN_TEST_DB not set; skipping DB integration tests")
	}
	ctx := context.Background()

	// Reset the schema for a clean, repeatable run.
	raw, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := raw.Exec(ctx, `DROP SCHEMA IF EXISTS protean CASCADE`); err != nil {
		raw.Close()
		t.Fatalf("drop schema: %v", err)
	}
	raw.Close()

	s, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := Migrate(ctx, s); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestMigrateIdempotent(t *testing.T) {
	s := testDB(t)
	// Running Migrate again must be a no-op (all files already recorded).
	if err := Migrate(context.Background(), s); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

func TestUsersAndSessions(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if n, _ := s.CountUsers(ctx); n != 0 {
		t.Fatalf("fresh DB should have 0 users, got %d", n)
	}
	u, err := s.CreateUser(ctx, "admin", "hash1", "admin")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := s.GetUserByUsernameAndSource(ctx, "admin", "local")
	if err != nil || got.ID != u.ID || got.PasswordHash != "hash1" {
		t.Fatalf("GetUserByUsernameAndSource: %+v err=%v", got, err)
	}
	if err := s.UpdateUserPassword(ctx, u.ID, "hash2"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	if got, _ := s.GetUserByUsernameAndSource(ctx, "admin", "local"); got.PasswordHash != "hash2" {
		t.Errorf("password not updated: %q", got.PasswordHash)
	}
	if err := s.SetUserTOTP(ctx, u.ID, "SECRET", true); err != nil {
		t.Fatalf("SetUserTOTP: %v", err)
	}

	// Sessions.
	exp := time.Now().Add(time.Hour)
	if err := s.CreateSession(ctx, u.ID, "tok-hash", exp); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sess, err := s.GetSession(ctx, "tok-hash")
	if err != nil || sess.UserID != u.ID || sess.Role != "admin" {
		t.Fatalf("GetSession: %+v err=%v", sess, err)
	}
	if err := s.DeleteSession(ctx, "tok-hash"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := s.GetSession(ctx, "tok-hash"); err == nil {
		t.Error("session should be gone")
	}
}

// TestAuthSourceUniqueness confirms migration 0038's composite unique
// constraint: the same username can exist once per auth_source (LDAP/OIDC
// accounts are deliberately separate entities from a local account of the
// same name), but not twice under the SAME source.
func TestAuthSourceUniqueness(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	local, err := s.CreateUser(ctx, "ivan", "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser (local): %v", err)
	}
	if local.AuthSource != "local" {
		t.Errorf("AuthSource = %q, want local", local.AuthSource)
	}

	ldapUser, err := s.UpsertExternalUser(ctx, "ivan", "ldap", "admin")
	if err != nil {
		t.Fatalf("UpsertExternalUser (ldap, same username as local): %v", err)
	}
	if ldapUser.ID == local.ID {
		t.Error("ldap account must be a distinct row from the local account of the same username")
	}
	if ldapUser.PasswordHash != "" {
		t.Errorf("external account must have no password hash, got %q", ldapUser.PasswordHash)
	}

	// Same username, same source ("local") must collide.
	if _, err := s.CreateUser(ctx, "ivan", "hash2", "admin"); err == nil {
		t.Error("expected a uniqueness violation creating a second local 'ivan'")
	}

	// Re-provisioning the same external account updates its role in place
	// (a group-membership change takes effect on next login) rather than
	// creating a third row.
	updated, err := s.UpsertExternalUser(ctx, "ivan", "ldap", "user")
	if err != nil {
		t.Fatalf("UpsertExternalUser (re-provision): %v", err)
	}
	if updated.ID != ldapUser.ID {
		t.Error("re-provisioning must update the existing row, not create a new one")
	}
	if updated.Role != "user" {
		t.Errorf("Role = %q, want user after re-provisioning", updated.Role)
	}
}

func TestSubnets(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	sn, err := s.CreateSubnet(ctx, "192.168.5.0/24", "office")
	if err != nil {
		t.Fatalf("CreateSubnet: %v", err)
	}
	list, err := s.ListAllSubnets(ctx)
	if err != nil || len(list) != 1 || list[0].CIDR != "192.168.5.0/24" {
		t.Fatalf("ListAllSubnets: %+v err=%v", list, err)
	}
	if err := s.DeleteSubnet(ctx, sn.ID); err != nil {
		t.Fatalf("DeleteSubnet: %v", err)
	}
	if list, _ := s.ListAllSubnets(ctx); len(list) != 0 {
		t.Errorf("subnet not deleted: %+v", list)
	}
}

func TestPeerSecretsAndReconcileList(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	if err := s.SavePeerSecret(ctx, "wg0", "pubA", []byte("encA")); err != nil {
		t.Fatalf("SavePeerSecret: %v", err)
	}
	_ = s.SavePeerSecret(ctx, "wg0", "pubB", []byte("encB"))
	blob, err := s.GetPeerSecret(ctx, "wg0", "pubA")
	if err != nil || string(blob) != "encA" {
		t.Fatalf("GetPeerSecret: %q err=%v", blob, err)
	}
	keys, err := s.ListPeerSecretKeys(ctx, "wg0")
	if err != nil || len(keys) != 2 {
		t.Fatalf("ListPeerSecretKeys: %v err=%v", keys, err)
	}
	if err := s.DeletePeerSecret(ctx, "wg0", "pubA"); err != nil {
		t.Fatalf("DeletePeerSecret: %v", err)
	}
	if _, err := s.GetPeerSecret(ctx, "wg0", "pubA"); err == nil {
		t.Error("secret should be gone")
	}
}

func TestCertsCAAndClientsAndCRL(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if err := s.SaveCAMaterial(ctx, CAMaterial{Provider: "openvpn", CertPEM: "CERT", EncKeyPEM: []byte("K"), Source: "internal"}); err != nil {
		t.Fatalf("SaveCAMaterial: %v", err)
	}
	m, err := s.GetCAMaterial(ctx, "openvpn")
	if err != nil || m.CertPEM != "CERT" || m.Source != "internal" {
		t.Fatalf("GetCAMaterial: %+v err=%v", m, err)
	}

	_ = s.SaveOpenVPNClient(ctx, OpenVPNClient{Provider: "default:openvpn", CN: "office-a", CertPEM: "C", EncKeyPEM: []byte("k"), Address: "10.8.0.2/32", Subnets: "192.168.5.0/24"})
	oc, err := s.GetOpenVPNClient(ctx, "default:openvpn", "office-a")
	if err != nil || oc.Address != "10.8.0.2/32" {
		t.Fatalf("GetOpenVPNClient: %+v err=%v", oc, err)
	}
	if list, _ := s.ListOpenVPNClients(ctx, "default:openvpn"); len(list) != 1 {
		t.Errorf("ListOpenVPNClients: %+v", list)
	}

	// IKEv2 client + server routes.
	_ = s.SaveIKEv2Client(ctx, IKEv2Client{Provider: "default:ikev2", CN: "phone", CertPEM: "C", EncKeyPEM: []byte("k"), P12Password: "pw", Address: "10.9.0.2/32"})
	ic, err := s.GetIKEv2Client(ctx, "default:ikev2", "phone")
	if err != nil || ic.P12Password != "pw" {
		t.Fatalf("GetIKEv2Client: %+v err=%v", ic, err)
	}
	if err := s.SaveCertServerRoutes(ctx, "ikev2", []string{"10.10.0.0/24", "192.168.5.0/24"}, true); err != nil {
		t.Fatalf("SaveCertServerRoutes: %v", err)
	}
	routes, egress, ok, err := s.GetCertServerRoutes(ctx, "ikev2")
	if err != nil || !ok || !egress || len(routes) != 2 {
		t.Fatalf("GetCertServerRoutes: routes=%v egress=%v ok=%v err=%v", routes, egress, ok, err)
	}

	// CRL: revocations + monotonic number.
	_ = s.AddRevokedCert(ctx, "openvpn", "12345", "office-a")
	_ = s.AddRevokedCert(ctx, "openvpn", "12345", "office-a") // idempotent
	rows, err := s.ListRevokedCerts(ctx, "openvpn")
	if err != nil || len(rows) != 1 || rows[0].Serial != "12345" {
		t.Fatalf("ListRevokedCerts: %+v err=%v", rows, err)
	}
	n1, _ := s.NextCRLNumber(ctx, "openvpn")
	n2, _ := s.NextCRLNumber(ctx, "openvpn")
	if n1 != 1 || n2 != 2 {
		t.Errorf("CRL numbers not monotonic: %d, %d", n1, n2)
	}

	// CRL import (adopting an existing server): bulk-insert preserving the
	// original RevokedAt, idempotent against a cert already recorded above,
	// and seeding crl_number without regressing it.
	importedAt := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	err = s.ImportRevokedCerts(ctx, "openvpn", []RevokedCertRow{
		{Serial: "12345", CN: "office-a", RevokedAt: importedAt}, // already present -- must stay untouched (ON CONFLICT DO NOTHING)
		{Serial: "99999", CN: "old-client", RevokedAt: importedAt},
	})
	if err != nil {
		t.Fatalf("ImportRevokedCerts: %v", err)
	}
	rows, err = s.ListRevokedCerts(ctx, "openvpn")
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListRevokedCerts after import: %+v err=%v", rows, err)
	}
	for _, r := range rows {
		if r.Serial == "12345" && r.RevokedAt.Equal(importedAt) {
			t.Errorf("import must not overwrite the pre-existing 12345 row's original RevokedAt")
		}
		if r.Serial == "99999" && !r.RevokedAt.Equal(importedAt) {
			t.Errorf("imported row 99999 RevokedAt = %v, want %v", r.RevokedAt, importedAt)
		}
	}

	if err := s.SeedCRLNumber(ctx, "openvpn", 50); err != nil {
		t.Fatalf("SeedCRLNumber(50): %v", err)
	}
	if n, _ := s.NextCRLNumber(ctx, "openvpn"); n != 51 {
		t.Errorf("NextCRLNumber after seeding to 50 = %d, want 51", n)
	}
	if err := s.SeedCRLNumber(ctx, "openvpn", 5); err != nil { // lower than current -- must not regress
		t.Fatalf("SeedCRLNumber(5): %v", err)
	}
	if n, _ := s.NextCRLNumber(ctx, "openvpn"); n != 52 {
		t.Errorf("SeedCRLNumber with a lower value regressed the counter: got %d, want 52", n)
	}
}

func TestExpiryDisabledCategoryMute(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	_ = s.SetPeerExpiry(ctx, "wg0", "pk1", past)
	_ = s.SetPeerExpiry(ctx, "wg0", "pk2", time.Now().Add(time.Hour))
	due, err := s.ListDuePeers(ctx)
	if err != nil || len(due) != 1 || due[0].PeerID != "pk1" {
		t.Fatalf("ListDuePeers: %+v err=%v", due, err)
	}
	m, _ := s.ExpiryForProvider(ctx, "wg0")
	if len(m) != 2 {
		t.Errorf("ExpiryForProvider: %+v", m)
	}
	_ = s.DeletePeerExpiry(ctx, "wg0", "pk1")

	_ = s.SaveDisabledPeer(ctx, DisabledPeer{Provider: "wg0", PublicKey: "pk3", Name: "n", AllowedIPs: "10.0.0.3/32"})
	if list, _ := s.ListDisabledPeers(ctx, "wg0"); len(list) != 1 {
		t.Errorf("ListDisabledPeers: %+v", list)
	}
	_ = s.DeleteDisabledPeer(ctx, "wg0", "pk3")

	_ = s.SetPeerCategory(ctx, "wg0", "pk1", "site")
	if c, _ := s.PeerCategories(ctx, "wg0"); c["pk1"] != "site" {
		t.Errorf("PeerCategories: %+v", c)
	}
	_ = s.SetPeerMuted(ctx, "wg0", "pk1", true)
	if mm, _ := s.MutedPeers(ctx, "wg0"); !mm["pk1"] {
		t.Errorf("MutedPeers: %+v", mm)
	}
}

func TestNotifyChannelsSettingsPending(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if err := s.SaveNotifyChannel(ctx, "telegram", true, []byte(`{"token":"x"}`)); err != nil {
		t.Fatalf("SaveNotifyChannel: %v", err)
	}
	ch, err := s.GetNotifyChannel(ctx, "telegram")
	if err != nil || !ch.Enabled {
		t.Fatalf("GetNotifyChannel: %+v err=%v", ch, err)
	}

	set, err := s.GetNotifySettings(ctx) // defaults on a fresh DB
	if err != nil {
		t.Fatalf("GetNotifySettings: %v", err)
	}
	set.EvUnknownPeer = true
	if err := s.SaveNotifySettings(ctx, set); err != nil {
		t.Fatalf("SaveNotifySettings: %v", err)
	}

	_ = s.AddNotifyPending(ctx, "event 1")
	_ = s.AddNotifyPending(ctx, "event 2")
	pend, err := s.ListNotifyPending(ctx)
	if err != nil || len(pend) != 2 {
		t.Fatalf("ListNotifyPending: %+v err=%v", pend, err)
	}
	_ = s.ClearNotifyPending(ctx)
	if pend, _ := s.ListNotifyPending(ctx); len(pend) != 0 {
		t.Errorf("pending not cleared: %+v", pend)
	}
}

func TestAuditAndBackupsAndProviderSettings(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	_ = s.AddAuditEntry(ctx, "admin", "peer.create", "wg0/pk")
	entries, err := s.ListAuditEntries(ctx, 10)
	if err != nil || len(entries) != 1 || entries[0].Action != "peer.create" {
		t.Fatalf("audit: %+v err=%v", entries, err)
	}

	_ = s.SaveConfBackup(ctx, "wg0", "[Interface]\n")
	if list, _ := s.ListConfBackups(ctx, "wg0"); len(list) != 1 {
		t.Errorf("ListConfBackups: %+v", list)
	}

	_ = s.SetProviderSettings(ctx, ProviderSettings{Provider: "wg0", MeshEnabled: true, InternetEgress: true})
	ps, err := s.GetProviderSettings(ctx, "wg0")
	if err != nil || !ps.MeshEnabled || !ps.InternetEgress {
		t.Fatalf("GetProviderSettings: %+v err=%v", ps, err)
	}
	// Absent row -> defaults.
	if def, _ := s.GetProviderSettings(ctx, "never-set"); def.MeshEnabled || def.InternetEgress {
		t.Errorf("absent settings should default off: %+v", def)
	}
}

func TestXrayInstance(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()
	if err := s.SaveXrayInstance(ctx, XrayInstance{
		Provider: "default:xray", Strategy: "reality-vless-tcp",
		EncParams: []byte("encP"), EncRelay: []byte("encR"),
	}); err != nil {
		t.Fatalf("SaveXrayInstance: %v", err)
	}
	x, err := s.GetXrayInstance(ctx, "default:xray")
	if err != nil || x.Strategy != "reality-vless-tcp" || string(x.EncParams) != "encP" || string(x.EncRelay) != "encR" {
		t.Fatalf("GetXrayInstance: %+v err=%v", x, err)
	}
	// Upsert without relay clears it.
	_ = s.SaveXrayInstance(ctx, XrayInstance{Provider: "default:xray", Strategy: "trojan-tcp-tls", EncParams: []byte("p2")})
	x2, _ := s.GetXrayInstance(ctx, "default:xray")
	if x2.Strategy != "trojan-tcp-tls" || len(x2.EncRelay) != 0 {
		t.Errorf("upsert not applied: %+v", x2)
	}
	// Xray clients.
	_ = s.SaveXrayClient(ctx, "default:xray", "alice", []byte("encA"))
	_ = s.SaveXrayClient(ctx, "default:xray", "bob", []byte("encB"))
	cls, err := s.ListXrayClients(ctx, "default:xray")
	if err != nil || len(cls) != 2 {
		t.Fatalf("ListXrayClients: %+v err=%v", cls, err)
	}
	if err := s.DeleteXrayClient(ctx, "default:xray", "alice"); err != nil {
		t.Fatalf("DeleteXrayClient: %v", err)
	}
	if cls, _ := s.ListXrayClients(ctx, "default:xray"); len(cls) != 1 || cls[0].Name != "bob" {
		t.Errorf("after delete: %+v", cls)
	}

	if err := s.DeleteXrayInstance(ctx, "default:xray"); err != nil {
		t.Fatalf("DeleteXrayInstance: %v", err)
	}
	if _, err := s.GetXrayInstance(ctx, "default:xray"); err == nil {
		t.Error("xray instance should be gone")
	}
}

func TestServersCRUD(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if n, _ := s.CountServers(ctx); n != 0 {
		t.Fatalf("fresh DB should have 0 servers, got %d", n)
	}
	srv := Server{ID: "default", Label: "HQ", Host: "10.0.0.1", Port: 22, SSHUser: "protean",
		EncKeyPEM: []byte("sealed"), HostKey: "ssh-ed25519 AAAA", PublicHost: "vpn.example.com"}
	if err := s.CreateServer(ctx, srv); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	got, err := s.GetServer(ctx, "default")
	if err != nil || got.Host != "10.0.0.1" || string(got.EncKeyPEM) != "sealed" || got.PublicHost != "vpn.example.com" {
		t.Fatalf("GetServer: %+v err=%v", got, err)
	}
	srv.Host = "10.0.0.2"
	if err := s.UpdateServer(ctx, srv); err != nil {
		t.Fatalf("UpdateServer: %v", err)
	}
	if got, _ := s.GetServer(ctx, "default"); got.Host != "10.0.0.2" {
		t.Errorf("host not updated: %q", got.Host)
	}
	if list, _ := s.ListServers(ctx); len(list) != 1 {
		t.Errorf("ListServers: %+v", list)
	}
	if err := s.DeleteServer(ctx, "default"); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if n, _ := s.CountServers(ctx); n != 0 {
		t.Errorf("server not deleted, count=%d", n)
	}
}

func TestPanelHost(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if _, err := s.GetPanelHost(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPanelHost on empty DB: err=%v, want ErrNotFound", err)
	}

	mk := func(id string) Server {
		return Server{ID: id, Label: id, Host: "10.0.0.1", Port: 22, SSHUser: "protean",
			EncKeyPEM: []byte("sealed"), HostKey: "ssh-ed25519 AAAA"}
	}
	if err := s.CreateServer(ctx, mk("srv-a")); err != nil {
		t.Fatalf("CreateServer srv-a: %v", err)
	}
	if err := s.CreateServer(ctx, mk("srv-b")); err != nil {
		t.Fatalf("CreateServer srv-b: %v", err)
	}

	if err := s.SetPanelHost(ctx, "srv-a"); err != nil {
		t.Fatalf("SetPanelHost srv-a: %v", err)
	}
	got, err := s.GetPanelHost(ctx)
	if err != nil || got.ID != "srv-a" {
		t.Fatalf("GetPanelHost = %+v, err=%v, want srv-a", got, err)
	}
	if srv, _ := s.GetServer(ctx, "srv-a"); !srv.PanelHost {
		t.Error("srv-a.PanelHost should be true after SetPanelHost")
	}

	// Re-flagging a different row must move the flag, not duplicate it --
	// the partial unique index (0039_panel_host.sql) enforces at most one
	// at the DB level; SetPanelHost's own transaction clears the old row
	// first so this never trips it.
	if err := s.SetPanelHost(ctx, "srv-b"); err != nil {
		t.Fatalf("SetPanelHost srv-b: %v", err)
	}
	got, err = s.GetPanelHost(ctx)
	if err != nil || got.ID != "srv-b" {
		t.Fatalf("GetPanelHost after re-flag = %+v, err=%v, want srv-b", got, err)
	}
	if srv, _ := s.GetServer(ctx, "srv-a"); srv.PanelHost {
		t.Error("srv-a.PanelHost should be false after re-flagging srv-b")
	}

	if err := s.SetPanelHost(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetPanelHost on unknown id: err=%v, want ErrNotFound", err)
	}
	// A failed SetPanelHost must not have cleared the existing flag (the
	// whole call runs in one transaction).
	if got, err := s.GetPanelHost(ctx); err != nil || got.ID != "srv-b" {
		t.Fatalf("panel host changed after a failed SetPanelHost: %+v, err=%v", got, err)
	}

	if err := s.ClearPanelHost(ctx); err != nil {
		t.Fatalf("ClearPanelHost: %v", err)
	}
	if _, err := s.GetPanelHost(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPanelHost after clear: err=%v, want ErrNotFound", err)
	}
	// Clearing with nothing set is a no-op, not an error.
	if err := s.ClearPanelHost(ctx); err != nil {
		t.Fatalf("ClearPanelHost on already-clear state: %v", err)
	}
}

func TestSingletonLock(t *testing.T) {
	url := os.Getenv("PROTEAN_TEST_DB")
	if url == "" {
		t.Skip("PROTEAN_TEST_DB not set")
	}
	_ = testDB(t) // ensures schema exists
	ctx := context.Background()

	a, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer a.Close()
	if err := a.AcquireSingletonLock(ctx); err != nil {
		t.Fatalf("first lock should succeed: %v", err)
	}

	b, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer b.Close()
	if err := b.AcquireSingletonLock(ctx); err == nil {
		t.Error("second lock should fail while the first is held")
	}
}

func TestUserRolesAndPeerOwnership(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	admin, err := s.CreateUser(ctx, "admin", "hash", "admin")
	if err != nil {
		t.Fatalf("CreateUser admin: %v", err)
	}
	portalUser, err := s.CreateUser(ctx, "ivanov", "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser portal: %v", err)
	}
	if portalUser.Role != "user" {
		t.Fatalf("role = %q, want \"user\"", portalUser.Role)
	}

	got, err := s.GetUserByID(ctx, portalUser.ID)
	if err != nil || got.Username != "ivanov" || got.Role != "user" {
		t.Fatalf("GetUserByID: %+v err=%v", got, err)
	}

	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("ListUsers: %+v err=%v", users, err)
	}
	if n, err := s.CountUsersByRole(ctx, "admin"); err != nil || n != 1 {
		t.Fatalf("CountUsersByRole(admin) = %d err=%v", n, err)
	}

	// Peer ownership round-trip.
	if _, ok, err := s.GetPeerOwnerUserID(ctx, "wg0", "peer-abc"); err != nil || ok {
		t.Fatalf("unassigned peer should report ok=false, got ok=%v err=%v", ok, err)
	}
	if err := s.SetPeerOwner(ctx, "wg0", "peer-abc", portalUser.ID); err != nil {
		t.Fatalf("SetPeerOwner: %v", err)
	}
	ownerID, ok, err := s.GetPeerOwnerUserID(ctx, "wg0", "peer-abc")
	if err != nil || !ok || ownerID != portalUser.ID {
		t.Fatalf("GetPeerOwnerUserID after set: id=%d ok=%v err=%v", ownerID, ok, err)
	}
	owned, err := s.ListOwnedPeerKeys(ctx, portalUser.ID)
	if err != nil || len(owned) != 1 || owned[0].Provider != "wg0" || owned[0].PeerKey != "peer-abc" {
		t.Fatalf("ListOwnedPeerKeys: %+v err=%v", owned, err)
	}
	rows, err := s.ListOwnersForProvider(ctx, "wg0")
	if err != nil || len(rows) != 1 || rows[0].Username != "ivanov" {
		t.Fatalf("ListOwnersForProvider: %+v err=%v", rows, err)
	}

	// Reassign to a different user (admin, just to prove upsert overwrites).
	if err := s.SetPeerOwner(ctx, "wg0", "peer-abc", admin.ID); err != nil {
		t.Fatalf("SetPeerOwner reassign: %v", err)
	}
	if ownerID, _, _ := s.GetPeerOwnerUserID(ctx, "wg0", "peer-abc"); ownerID != admin.ID {
		t.Errorf("after reassign, owner = %d, want %d", ownerID, admin.ID)
	}

	if err := s.ClearPeerOwner(ctx, "wg0", "peer-abc"); err != nil {
		t.Fatalf("ClearPeerOwner: %v", err)
	}
	if _, ok, _ := s.GetPeerOwnerUserID(ctx, "wg0", "peer-abc"); ok {
		t.Error("peer should be unassigned after ClearPeerOwner")
	}

	// Deleting the owning user cascades and removes their ownership rows
	// (ON DELETE CASCADE) -- reassign first, then delete.
	if err := s.SetPeerOwner(ctx, "wg0", "peer-xyz", portalUser.ID); err != nil {
		t.Fatalf("SetPeerOwner: %v", err)
	}
	if err := s.DeleteUser(ctx, portalUser.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok, _ := s.GetPeerOwnerUserID(ctx, "wg0", "peer-xyz"); ok {
		t.Error("peer_owner row should cascade-delete with its user")
	}
}

func TestServerInstanceLabels(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	srv := Server{ID: "hq", Label: "HQ", Host: "10.0.0.1", Port: 22, SSHUser: "protean", EncKeyPEM: []byte("sealed")}
	if err := s.CreateServer(ctx, srv); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := s.CreateServerInstance(ctx, ServerInstance{ServerID: "hq", LocalName: "wg0", Type: "wireguard"}); err != nil {
		t.Fatalf("CreateServerInstance: %v", err)
	}

	list, err := s.ListServerInstances(ctx, "hq")
	if err != nil || len(list) != 1 || list[0].Label != "" {
		t.Fatalf("ListServerInstances (no label yet): %+v err=%v", list, err)
	}
	if labels, err := s.ListAllServerInstanceLabels(ctx); err != nil || len(labels) != 0 {
		t.Fatalf("ListAllServerInstanceLabels (no labels yet) = %+v err=%v", labels, err)
	}

	if err := s.UpdateServerInstanceLabel(ctx, "hq", "wg0", "Германия"); err != nil {
		t.Fatalf("UpdateServerInstanceLabel: %v", err)
	}
	list, err = s.ListServerInstances(ctx, "hq")
	if err != nil || len(list) != 1 || list[0].Label != "Германия" {
		t.Fatalf("ListServerInstances (after label): %+v err=%v", list, err)
	}
	labels, err := s.ListAllServerInstanceLabels(ctx)
	if err != nil || labels["hq:wg0"] != "Германия" {
		t.Fatalf("ListAllServerInstanceLabels = %+v err=%v", labels, err)
	}

	if err := s.UpdateServerInstanceLabel(ctx, "hq", "doesnotexist", "x"); err != ErrNotFound {
		t.Errorf("UpdateServerInstanceLabel on unknown instance = %v, want ErrNotFound", err)
	}

	// portal_visible: explicit opt-in, defaults false.
	if visible, err := s.ListAllServerInstancePortalVisibility(ctx); err != nil || len(visible) != 0 {
		t.Fatalf("ListAllServerInstancePortalVisibility (default false) = %+v err=%v", visible, err)
	}
	if err := s.UpdateServerInstanceVisibility(ctx, "hq", "wg0", true); err != nil {
		t.Fatalf("UpdateServerInstanceVisibility: %v", err)
	}
	visible, err := s.ListAllServerInstancePortalVisibility(ctx)
	if err != nil || !visible["hq:wg0"] {
		t.Fatalf("ListAllServerInstancePortalVisibility (after enable) = %+v err=%v", visible, err)
	}
	if err := s.UpdateServerInstanceVisibility(ctx, "hq", "wg0", false); err != nil {
		t.Fatalf("UpdateServerInstanceVisibility (disable): %v", err)
	}
	if visible, err := s.ListAllServerInstancePortalVisibility(ctx); err != nil || visible["hq:wg0"] {
		t.Fatalf("ListAllServerInstancePortalVisibility (after disable) = %+v err=%v", visible, err)
	}
	if err := s.UpdateServerInstanceVisibility(ctx, "hq", "doesnotexist", true); err != ErrNotFound {
		t.Errorf("UpdateServerInstanceVisibility on unknown instance = %v, want ErrNotFound", err)
	}

	// description: admin-settable note, defaults empty, omitted from
	// ListAllServerInstanceDescriptions until set.
	if descriptions, err := s.ListAllServerInstanceDescriptions(ctx); err != nil || len(descriptions) != 0 {
		t.Fatalf("ListAllServerInstanceDescriptions (no descriptions yet) = %+v err=%v", descriptions, err)
	}
	if err := s.UpdateServerInstanceDescription(ctx, "hq", "wg0", "домашняя сеть, egress запрещён"); err != nil {
		t.Fatalf("UpdateServerInstanceDescription: %v", err)
	}
	list, err = s.ListServerInstances(ctx, "hq")
	if err != nil || len(list) != 1 || list[0].Description != "домашняя сеть, egress запрещён" {
		t.Fatalf("ListServerInstances (after description): %+v err=%v", list, err)
	}
	descriptions, err := s.ListAllServerInstanceDescriptions(ctx)
	if err != nil || descriptions["hq:wg0"] != "домашняя сеть, egress запрещён" {
		t.Fatalf("ListAllServerInstanceDescriptions = %+v err=%v", descriptions, err)
	}
	if err := s.UpdateServerInstanceDescription(ctx, "hq", "doesnotexist", "x"); err != ErrNotFound {
		t.Errorf("UpdateServerInstanceDescription on unknown instance = %v, want ErrNotFound", err)
	}

	// UpdateServerInstanceConfig: merge-patch semantics, existing keys survive.
	if err := s.CreateServerInstance(ctx, ServerInstance{
		ServerID: "hq", LocalName: "ovpn0", Type: "openvpn",
		Config: map[string]string{"listen_port": "1194"},
	}); err != nil {
		t.Fatalf("CreateServerInstance (openvpn): %v", err)
	}
	if err := s.UpdateServerInstanceConfig(ctx, "hq", "ovpn0", map[string]string{"mtu": "1400", "mssfix": "1350"}); err != nil {
		t.Fatalf("UpdateServerInstanceConfig: %v", err)
	}
	list, err = s.ListServerInstances(ctx, "hq")
	if err != nil {
		t.Fatalf("ListServerInstances: %v", err)
	}
	var ovpn *ServerInstance
	for i := range list {
		if list[i].LocalName == "ovpn0" {
			ovpn = &list[i]
		}
	}
	if ovpn == nil {
		t.Fatal("ovpn0 instance not found")
	}
	if ovpn.Config["listen_port"] != "1194" || ovpn.Config["mtu"] != "1400" || ovpn.Config["mssfix"] != "1350" {
		t.Errorf("Config after patch = %+v, want listen_port preserved + mtu/mssfix set", ovpn.Config)
	}
	if err := s.UpdateServerInstanceConfig(ctx, "hq", "doesnotexist", map[string]string{"mtu": "1"}); err != ErrNotFound {
		t.Errorf("UpdateServerInstanceConfig on unknown instance = %v, want ErrNotFound", err)
	}
}

func TestAccessRequests(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	u, err := s.CreateUser(ctx, "ivanov", "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	ar, err := s.UpsertRequest(ctx, u.ID, "hq:wg0")
	if err != nil || ar.Status != "pending" {
		t.Fatalf("UpsertRequest (create) = %+v err=%v", ar, err)
	}

	got, err := s.GetRequest(ctx, ar.ID)
	if err != nil || got.Username != "ivanov" || got.Provider != "hq:wg0" || got.Status != "pending" {
		t.Fatalf("GetRequest: %+v err=%v", got, err)
	}

	if err := s.SetRequestStatus(ctx, ar.ID, "approved"); err != nil {
		t.Fatalf("SetRequestStatus: %v", err)
	}
	if pending, found, err := s.FindApprovedRequestForProvider(ctx, "hq:wg0"); err != nil || !found || pending.ID != ar.ID {
		t.Fatalf("FindApprovedRequestForProvider = %+v found=%v err=%v", pending, found, err)
	}

	if err := s.SetRequestStatus(ctx, ar.ID, "granted"); err != nil {
		t.Fatalf("SetRequestStatus(granted): %v", err)
	}
	if _, found, err := s.FindApprovedRequestForProvider(ctx, "hq:wg0"); err != nil || found {
		t.Fatalf("FindApprovedRequestForProvider after granted: found=%v err=%v", found, err)
	}

	// Deny, then re-request via upsert -- same row (UNIQUE(user_id, provider)), back to pending.
	if err := s.SetRequestStatus(ctx, ar.ID, "denied"); err != nil {
		t.Fatalf("SetRequestStatus(denied): %v", err)
	}
	reopened, err := s.UpsertRequest(ctx, u.ID, "hq:wg0")
	if err != nil || reopened.ID != ar.ID || reopened.Status != "pending" {
		t.Fatalf("UpsertRequest (reopen) = %+v err=%v", reopened, err)
	}

	all, err := s.ListAllRequests(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListAllRequests: %+v err=%v", all, err)
	}
	mine, err := s.ListRequestsForUser(ctx, u.ID)
	if err != nil || len(mine) != 1 {
		t.Fatalf("ListRequestsForUser: %+v err=%v", mine, err)
	}
}

func TestTLSState(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	// Defaults before any row exists.
	got, err := s.GetTLSState(ctx)
	if err != nil || got.Mode != "self_signed" || got.SSKeyAlgo != "ecdsa_p256" {
		t.Fatalf("GetTLSState (default) = %+v err=%v", got, err)
	}

	want := TLSState{
		Mode: "acme", SSKeyAlgo: "rsa_4096", SSValidityDays: 90, SSRenewBeforeDays: 20, SSSans: "vpn.example.com,203.0.113.5",
		AcmeDirectoryURL: "https://acme.example.internal/directory", AcmeDomains: "vpn.example.com", AcmeEmail: "admin@example.com",
		AcmeChallenge: "http-01", AcmeTrustRootPEM: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		ManualCertPEM: "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----", ManualKeyEnc: []byte("sealed-key"),
	}
	if err := s.SetTLSState(ctx, want); err != nil {
		t.Fatalf("SetTLSState: %v", err)
	}
	got, err = s.GetTLSState(ctx)
	if err != nil {
		t.Fatalf("GetTLSState: %v", err)
	}
	// Compared field-by-field, not via == -- ManualKeyEnc is a []byte, which
	// makes the whole struct non-comparable.
	if got.Mode != want.Mode || got.SSKeyAlgo != want.SSKeyAlgo || got.SSValidityDays != want.SSValidityDays ||
		got.SSRenewBeforeDays != want.SSRenewBeforeDays || got.SSSans != want.SSSans ||
		got.AcmeDirectoryURL != want.AcmeDirectoryURL || got.AcmeDomains != want.AcmeDomains ||
		got.AcmeEmail != want.AcmeEmail || got.AcmeChallenge != want.AcmeChallenge || got.AcmeTrustRootPEM != want.AcmeTrustRootPEM ||
		got.ManualCertPEM != want.ManualCertPEM || string(got.ManualKeyEnc) != string(want.ManualKeyEnc) {
		t.Fatalf("GetTLSState after set = %+v, want %+v", got, want)
	}

	// Upsert semantics: a second Set overwrites, doesn't create a second row.
	want.Mode = "manual"
	if err := s.SetTLSState(ctx, want); err != nil {
		t.Fatalf("SetTLSState (update): %v", err)
	}
	got, err = s.GetTLSState(ctx)
	if err != nil || got.Mode != "manual" {
		t.Fatalf("GetTLSState after update = %+v err=%v", got, err)
	}
}

func TestTLSSelfSignedAndAcmeCache(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if _, found, err := s.GetTLSSelfSigned(ctx); err != nil || found {
		t.Fatalf("GetTLSSelfSigned (none yet) = found=%v err=%v", found, err)
	}

	if err := s.SaveTLSSelfSignedCA(ctx, "ca-cert-pem", []byte("sealed-ca-key")); err != nil {
		t.Fatalf("SaveTLSSelfSignedCA: %v", err)
	}
	ss, found, err := s.GetTLSSelfSigned(ctx)
	if err != nil || !found || ss.CACertPEM != "ca-cert-pem" || string(ss.CAKeyEnc) != "sealed-ca-key" {
		t.Fatalf("GetTLSSelfSigned (after CA save) = %+v found=%v err=%v", ss, found, err)
	}
	if ss.LeafCertPEM != "" {
		t.Errorf("expected no leaf yet, got %q", ss.LeafCertPEM)
	}

	issuedAt := time.Now().Truncate(time.Second)
	expiresAt := issuedAt.AddDate(1, 0, 0)
	if err := s.SaveTLSSelfSignedLeaf(ctx, "leaf-cert-pem", []byte("sealed-leaf-key"), issuedAt, expiresAt); err != nil {
		t.Fatalf("SaveTLSSelfSignedLeaf: %v", err)
	}
	ss, found, err = s.GetTLSSelfSigned(ctx)
	if err != nil || !found || ss.LeafCertPEM != "leaf-cert-pem" || string(ss.LeafKeyEnc) != "sealed-leaf-key" {
		t.Fatalf("GetTLSSelfSigned (after leaf save) = %+v found=%v err=%v", ss, found, err)
	}
	// CA must survive a leaf-only update.
	if ss.CACertPEM != "ca-cert-pem" {
		t.Errorf("CA cert lost after leaf save: %q", ss.CACertPEM)
	}
	if !ss.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", ss.ExpiresAt, expiresAt)
	}

	// ACME cache: Get/Put/Delete round trip.
	if _, ok, err := s.AcmeCacheGet(ctx, "acct-key"); err != nil || ok {
		t.Fatalf("AcmeCacheGet (missing) = ok=%v err=%v", ok, err)
	}
	if err := s.AcmeCachePut(ctx, "acct-key", []byte("sealed-blob")); err != nil {
		t.Fatalf("AcmeCachePut: %v", err)
	}
	if v, ok, err := s.AcmeCacheGet(ctx, "acct-key"); err != nil || !ok || string(v) != "sealed-blob" {
		t.Fatalf("AcmeCacheGet = %q ok=%v err=%v", v, ok, err)
	}
	if err := s.AcmeCachePut(ctx, "acct-key", []byte("updated-blob")); err != nil {
		t.Fatalf("AcmeCachePut (update): %v", err)
	}
	if v, _, _ := s.AcmeCacheGet(ctx, "acct-key"); string(v) != "updated-blob" {
		t.Errorf("AcmeCacheGet after update = %q, want updated-blob", v)
	}
	if err := s.AcmeCacheDelete(ctx, "acct-key"); err != nil {
		t.Fatalf("AcmeCacheDelete: %v", err)
	}
	if _, ok, _ := s.AcmeCacheGet(ctx, "acct-key"); ok {
		t.Error("key still present after Delete")
	}
}

func TestLoginSecuritySettingsAndIPRules(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	got, err := s.GetLoginSecuritySettings(ctx)
	if err != nil || !got.Enabled || got.FailThreshold != 3 || got.EscalationFactor != 2 {
		t.Fatalf("GetLoginSecuritySettings (default) = %+v err=%v", got, err)
	}

	want := LoginSecuritySettings{
		Enabled: true, TrackByUsername: true, TrackByIP: false,
		FailThreshold: 5, CountWindowMinutes: 10, BanBaseMinutes: 15,
		EscalationFactor: 3, EscalationResetMinutes: 120, MaxBanMinutes: 720,
	}
	if err := s.SetLoginSecuritySettings(ctx, want); err != nil {
		t.Fatalf("SetLoginSecuritySettings: %v", err)
	}
	got, err = s.GetLoginSecuritySettings(ctx)
	if err != nil || got != want {
		t.Fatalf("GetLoginSecuritySettings after set = %+v err=%v, want %+v", got, err, want)
	}

	if rules, err := s.ListLoginIPRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("ListLoginIPRules (empty) = %+v err=%v", rules, err)
	}
	if err := s.AddLoginIPRule(ctx, LoginIPRule{IPOrCIDR: "10.0.0.0/24", Kind: "allow", Note: "office"}); err != nil {
		t.Fatalf("AddLoginIPRule: %v", err)
	}
	rules, err := s.ListLoginIPRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Kind != "allow" || rules[0].Note != "office" {
		t.Fatalf("ListLoginIPRules (after add) = %+v err=%v", rules, err)
	}
	// Upsert semantics: re-adding the same key updates kind/note in place.
	if err := s.AddLoginIPRule(ctx, LoginIPRule{IPOrCIDR: "10.0.0.0/24", Kind: "deny", Note: "revoked"}); err != nil {
		t.Fatalf("AddLoginIPRule (update): %v", err)
	}
	rules, err = s.ListLoginIPRules(ctx)
	if err != nil || len(rules) != 1 || rules[0].Kind != "deny" {
		t.Fatalf("ListLoginIPRules (after update) = %+v err=%v", rules, err)
	}
	if err := s.DeleteLoginIPRule(ctx, "10.0.0.0/24"); err != nil {
		t.Fatalf("DeleteLoginIPRule: %v", err)
	}
	if rules, err := s.ListLoginIPRules(ctx); err != nil || len(rules) != 0 {
		t.Fatalf("ListLoginIPRules (after delete) = %+v err=%v", rules, err)
	}
}

func TestLoginAttemptsAndBanState(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	// CountRecentFailures: the real sliding-window query (faked in the
	// auth package's own unit tests -- this is what proves that fake
	// actually matches reality).
	if err := s.RecordLoginAttempt(ctx, "alice", "9.9.9.9", false, "bad_password"); err != nil {
		t.Fatalf("RecordLoginAttempt: %v", err)
	}
	if err := s.RecordLoginAttempt(ctx, "alice", "9.9.9.9", false, "bad_password"); err != nil {
		t.Fatalf("RecordLoginAttempt: %v", err)
	}
	if err := s.RecordLoginAttempt(ctx, "alice", "9.9.9.9", true, ""); err != nil {
		t.Fatalf("RecordLoginAttempt (success): %v", err)
	}
	n, err := s.CountRecentFailures(ctx, "username", "alice", time.Now().Add(-time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("CountRecentFailures(username) = %d err=%v, want 2 (success doesn't count)", n, err)
	}
	n, err = s.CountRecentFailures(ctx, "ip", "9.9.9.9", time.Now().Add(-time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("CountRecentFailures(ip) = %d err=%v, want 2", n, err)
	}
	// Outside the window: nothing counts.
	n, err = s.CountRecentFailures(ctx, "username", "alice", time.Now().Add(time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("CountRecentFailures (future cutoff) = %d err=%v, want 0", n, err)
	}

	if _, found, err := s.GetLoginBanState(ctx, "ip", "9.9.9.9"); err != nil || found {
		t.Fatalf("GetLoginBanState (none yet) found=%v err=%v", found, err)
	}
	until := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	if err := s.UpsertLoginBanState(ctx, "ip", "9.9.9.9", until, 1); err != nil {
		t.Fatalf("UpsertLoginBanState: %v", err)
	}
	ban, found, err := s.GetLoginBanState(ctx, "ip", "9.9.9.9")
	if err != nil || !found || ban.EscalationLevel != 1 || !ban.BannedUntil.Equal(until) {
		t.Fatalf("GetLoginBanState (after upsert) = %+v found=%v err=%v", ban, found, err)
	}

	active, err := s.ListActiveLoginBans(ctx)
	if err != nil || len(active) != 1 || active[0].KeyValue != "9.9.9.9" {
		t.Fatalf("ListActiveLoginBans = %+v err=%v", active, err)
	}

	if err := s.ClearLoginBanState(ctx, "ip", "9.9.9.9"); err != nil {
		t.Fatalf("ClearLoginBanState: %v", err)
	}
	if active, err := s.ListActiveLoginBans(ctx); err != nil || len(active) != 0 {
		t.Fatalf("ListActiveLoginBans (after clear) = %+v err=%v", active, err)
	}

	recent, err := s.ListRecentLoginAttempts(ctx, 10)
	if err != nil || len(recent) != 3 {
		t.Fatalf("ListRecentLoginAttempts = %+v err=%v, want 3 rows", recent, err)
	}

	stats, err := s.GetLoginAttemptStats(ctx, time.Now().Add(-time.Hour), 5)
	if err != nil || stats.TotalAttempts != 3 || stats.FailedAttempts != 2 {
		t.Fatalf("GetLoginAttemptStats = %+v err=%v, want total=3 failed=2", stats, err)
	}
	if len(stats.TopIPs) != 1 || stats.TopIPs[0].IP != "9.9.9.9" || stats.TopIPs[0].Count != 2 {
		t.Fatalf("GetLoginAttemptStats.TopIPs = %+v, want one entry 9.9.9.9=2", stats.TopIPs)
	}
}

func TestPasswordPolicySettingsAndUserPasswordChangedAt(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	got, err := s.GetPasswordPolicySettings(ctx)
	if err != nil || got.MinLength != 8 || got.MaxAgeDays != 0 {
		t.Fatalf("GetPasswordPolicySettings (default) = %+v err=%v", got, err)
	}

	want := PasswordPolicySettings{
		MinLength: 12, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSymbol: true, MaxAgeDays: 90,
	}
	if err := s.SetPasswordPolicySettings(ctx, want); err != nil {
		t.Fatalf("SetPasswordPolicySettings: %v", err)
	}
	got, err = s.GetPasswordPolicySettings(ctx)
	if err != nil || got != want {
		t.Fatalf("GetPasswordPolicySettings after set = %+v err=%v, want %+v", got, err, want)
	}

	u, err := s.CreateUser(ctx, "pwtest", "hash", "user")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.PasswordChangedAt.IsZero() {
		t.Error("PasswordChangedAt should be set at creation time (column default now())")
	}
	before := u.PasswordChangedAt

	time.Sleep(10 * time.Millisecond)
	if err := s.UpdateUserPassword(ctx, u.ID, "newhash"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	after, err := s.GetUserByUsernameAndSource(ctx, "pwtest", "local")
	if err != nil {
		t.Fatalf("GetUserByUsernameAndSource: %v", err)
	}
	if !after.PasswordChangedAt.After(before) {
		t.Errorf("PasswordChangedAt did not advance after UpdateUserPassword: before=%v after=%v", before, after.PasswordChangedAt)
	}
}

func TestConnectionHistory(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	now := time.Now().Truncate(time.Second)
	if err := s.InsertConnectionEvent(ctx, now, "hq:wg0", "pubkey1", "laptop", "connect"); err != nil {
		t.Fatalf("InsertConnectionEvent (connect): %v", err)
	}
	if err := s.InsertConnectionEvent(ctx, now.Add(time.Minute), "hq:wg0", "pubkey1", "laptop", "disconnect"); err != nil {
		t.Fatalf("InsertConnectionEvent (disconnect): %v", err)
	}
	if err := s.InsertConnectionEvent(ctx, now, "hq:wg1", "pubkey2", "phone", "connect"); err != nil {
		t.Fatalf("InsertConnectionEvent (other provider): %v", err)
	}

	all, err := s.ListConnectionHistory(ctx, ConnectionHistoryFilter{Since: now.Add(-time.Hour)})
	if err != nil || len(all) != 3 {
		t.Fatalf("ListConnectionHistory (unfiltered) = %+v err=%v, want 3 rows", all, err)
	}
	// Newest first.
	if all[0].Event != "disconnect" && all[0].Event != "connect" {
		t.Fatalf("unexpected ordering: %+v", all)
	}

	byProvider, err := s.ListConnectionHistory(ctx, ConnectionHistoryFilter{Provider: "hq:wg0", Since: now.Add(-time.Hour)})
	if err != nil || len(byProvider) != 2 {
		t.Fatalf("ListConnectionHistory (provider filter) = %+v err=%v, want 2 rows", byProvider, err)
	}

	byPeer, err := s.ListConnectionHistory(ctx, ConnectionHistoryFilter{PeerID: "pubkey2", Since: now.Add(-time.Hour)})
	if err != nil || len(byPeer) != 1 || byPeer[0].PeerName != "phone" {
		t.Fatalf("ListConnectionHistory (peer filter) = %+v err=%v", byPeer, err)
	}

	// Outside the window: nothing.
	if none, err := s.ListConnectionHistory(ctx, ConnectionHistoryFilter{Since: now.Add(time.Hour)}); err != nil || len(none) != 0 {
		t.Fatalf("ListConnectionHistory (future cutoff) = %+v err=%v, want 0", none, err)
	}

	if err := s.PruneConnectionHistory(ctx, now.Add(30*time.Second)); err != nil {
		t.Fatalf("PruneConnectionHistory: %v", err)
	}
	remaining, err := s.ListConnectionHistory(ctx, ConnectionHistoryFilter{Since: now.Add(-time.Hour)})
	if err != nil || len(remaining) != 1 || remaining[0].Event != "disconnect" {
		t.Fatalf("ListConnectionHistory (after prune) = %+v err=%v, want only the disconnect row", remaining, err)
	}
}

func TestNodesAndNodePeers(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	router, err := s.CreateNode(ctx, Node{Name: "Keenetic-Office", Kind: "router", Role: "network_node", Description: "office LAN"})
	if err != nil {
		t.Fatalf("CreateNode router: %v", err)
	}
	if router.ID == 0 {
		t.Fatalf("CreateNode did not assign an id: %+v", router)
	}
	member, err := s.CreateNode(ctx, Node{Name: "backup-server", Kind: "device", Role: "member"})
	if err != nil {
		t.Fatalf("CreateNode member: %v", err)
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("ListNodes: %+v err=%v", nodes, err)
	}

	got, err := s.GetNode(ctx, router.ID)
	if err != nil || got.Name != "Keenetic-Office" || got.Kind != "router" || got.Role != "network_node" {
		t.Fatalf("GetNode: %+v err=%v", got, err)
	}

	if err := s.UpdateNode(ctx, router.ID, "Keenetic-Office-2", "router", "network_node", "renamed"); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if got, _ := s.GetNode(ctx, router.ID); got.Name != "Keenetic-Office-2" || got.Description != "renamed" {
		t.Fatalf("GetNode after update: %+v", got)
	}
	if err := s.UpdateNode(ctx, 999999, "x", "router", "member", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateNode unknown id: err=%v, want ErrNotFound", err)
	}

	// node_peer ownership round-trip, parallel to peer_owner but on a
	// completely separate table (see nodes.go/node_peer.go for why).
	if _, ok, err := s.GetNodePeerOwnerID(ctx, "srv:wg0", "peer-router"); err != nil || ok {
		t.Fatalf("unassigned peer should report ok=false, got ok=%v err=%v", ok, err)
	}
	if err := s.SetNodePeer(ctx, "srv:wg0", "peer-router", router.ID); err != nil {
		t.Fatalf("SetNodePeer: %v", err)
	}
	nodeID, ok, err := s.GetNodePeerOwnerID(ctx, "srv:wg0", "peer-router")
	if err != nil || !ok || nodeID != router.ID {
		t.Fatalf("GetNodePeerOwnerID after set: id=%d ok=%v err=%v", nodeID, ok, err)
	}
	owned, err := s.ListNodeOwnedPeerKeys(ctx, router.ID)
	if err != nil || len(owned) != 1 || owned[0].Provider != "srv:wg0" || owned[0].PeerKey != "peer-router" {
		t.Fatalf("ListNodeOwnedPeerKeys: %+v err=%v", owned, err)
	}
	rows, err := s.ListNodeOwnersForProvider(ctx, "srv:wg0")
	if err != nil || len(rows) != 1 || rows[0].NodeName != "Keenetic-Office-2" {
		t.Fatalf("ListNodeOwnersForProvider: %+v err=%v", rows, err)
	}

	// HasNetworkNodePeer: the safety guard behind "1 network_node = 1
	// dedicated instance" -- must report true once router (role
	// network_node) owns a peer here, false when excluding router itself
	// (a node re-checking against its own existing grant), and false for
	// a member-role node (they're allowed to share instances freely).
	if has, err := s.HasNetworkNodePeer(ctx, "srv:wg0", 0); err != nil || !has {
		t.Fatalf("HasNetworkNodePeer = %v err=%v, want true", has, err)
	}
	if has, err := s.HasNetworkNodePeer(ctx, "srv:wg0", router.ID); err != nil || has {
		t.Fatalf("HasNetworkNodePeer excluding self = %v err=%v, want false", has, err)
	}
	if err := s.SetNodePeer(ctx, "srv:wg1", "peer-member", member.ID); err != nil {
		t.Fatalf("SetNodePeer member: %v", err)
	}
	if has, err := s.HasNetworkNodePeer(ctx, "srv:wg1", 0); err != nil || has {
		t.Fatalf("HasNetworkNodePeer for a member-role node's instance = %v err=%v, want false", has, err)
	}

	if err := s.ClearNodePeer(ctx, "srv:wg0", "peer-router"); err != nil {
		t.Fatalf("ClearNodePeer: %v", err)
	}
	if _, ok, _ := s.GetNodePeerOwnerID(ctx, "srv:wg0", "peer-router"); ok {
		t.Error("peer should be unassigned after ClearNodePeer")
	}

	// Deleting a node cascades and removes its node_peer rows.
	if err := s.SetNodePeer(ctx, "srv:wg0", "peer-again", router.ID); err != nil {
		t.Fatalf("SetNodePeer: %v", err)
	}
	if err := s.DeleteNode(ctx, router.ID); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, ok, _ := s.GetNodePeerOwnerID(ctx, "srv:wg0", "peer-again"); ok {
		t.Error("node_peer row should be gone after DeleteNode (ON DELETE CASCADE)")
	}
	if _, err := s.GetNode(ctx, router.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNode after delete: err=%v, want ErrNotFound", err)
	}
}

func TestFirewallPolicyAndRules(t *testing.T) {
	s := testDB(t)
	ctx := context.Background()

	if err := s.CreateServer(ctx, Server{ID: "fw-srv", Label: "fw", Host: "10.0.0.1", Port: 22, SSHUser: "protean",
		EncKeyPEM: []byte("sealed"), HostKey: "ssh-ed25519 AAAA"}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	// No row yet -- sensible defaults, not an error.
	p, err := s.GetFirewallPolicy(ctx, "fw-srv")
	if err != nil {
		t.Fatalf("GetFirewallPolicy (no row): %v", err)
	}
	if p.Enabled || p.DefaultIncoming != "drop" || p.RollbackWindowSecs != 300 {
		t.Fatalf("default policy = %+v, want disabled/drop/300", p)
	}

	p.Enabled = true
	p.DefaultIncoming = "drop"
	p.RollbackWindowSecs = 120
	if err := s.UpsertFirewallPolicy(ctx, p); err != nil {
		t.Fatalf("UpsertFirewallPolicy: %v", err)
	}
	got, err := s.GetFirewallPolicy(ctx, "fw-srv")
	if err != nil || !got.Enabled || got.RollbackWindowSecs != 120 {
		t.Fatalf("GetFirewallPolicy after upsert = %+v, err=%v", got, err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.SetLastApplied(ctx, "fw-srv", "*filter\n:INPUT DROP\nCOMMIT\n", now); err != nil {
		t.Fatalf("SetLastApplied: %v", err)
	}
	got, _ = s.GetFirewallPolicy(ctx, "fw-srv")
	if got.LastAppliedRuleset == "" || got.LastAppliedAt == nil || !got.LastAppliedAt.Equal(now) {
		t.Fatalf("GetFirewallPolicy after SetLastApplied = %+v", got)
	}
	if got.LastConfirmedAt != nil {
		t.Fatalf("LastConfirmedAt should still be nil before SetLastConfirmed, got %v", got.LastConfirmedAt)
	}
	if err := s.SetLastConfirmed(ctx, "fw-srv", now); err != nil {
		t.Fatalf("SetLastConfirmed: %v", err)
	}
	got, _ = s.GetFirewallPolicy(ctx, "fw-srv")
	if got.LastConfirmedAt == nil || !got.LastConfirmedAt.Equal(now) {
		t.Fatalf("LastConfirmedAt after SetLastConfirmed = %v", got.LastConfirmedAt)
	}
	// last_applied_ruleset must survive a SetLastConfirmed call (it only
	// touches last_confirmed_at), not get clobbered back to empty.
	if got.LastAppliedRuleset == "" {
		t.Error("last_applied_ruleset was wiped by SetLastConfirmed")
	}

	rules := []FirewallRule{
		{ServerID: "fw-srv", Ordering: 1, Action: "accept", Proto: "tcp", PortSpec: "443", SourceCIDR: "", Comment: "https", Enabled: true},
		{ServerID: "fw-srv", Ordering: 2, Action: "drop", Proto: "any", PortSpec: "", SourceCIDR: "203.0.113.0/24", Comment: "block", Enabled: false},
	}
	if err := s.ReplaceFirewallRules(ctx, "fw-srv", rules); err != nil {
		t.Fatalf("ReplaceFirewallRules: %v", err)
	}
	list, err := s.ListFirewallRules(ctx, "fw-srv")
	if err != nil || len(list) != 2 || list[0].PortSpec != "443" || list[1].SourceCIDR != "203.0.113.0/24" {
		t.Fatalf("ListFirewallRules = %+v, err=%v", list, err)
	}

	// Replacing again with a smaller set must not leave stale rows behind.
	if err := s.ReplaceFirewallRules(ctx, "fw-srv", rules[:1]); err != nil {
		t.Fatalf("ReplaceFirewallRules (shrink): %v", err)
	}
	list, err = s.ListFirewallRules(ctx, "fw-srv")
	if err != nil || len(list) != 1 {
		t.Fatalf("ListFirewallRules after shrink = %+v, err=%v", list, err)
	}

	// Deleting the server must cascade both tables (ON DELETE CASCADE).
	if err := s.DeleteServer(ctx, "fw-srv"); err != nil {
		t.Fatalf("DeleteServer: %v", err)
	}
	if list, _ := s.ListFirewallRules(ctx, "fw-srv"); len(list) != 0 {
		t.Errorf("firewall_rules not cascaded on server delete: %+v", list)
	}
	if p, err := s.GetFirewallPolicy(ctx, "fw-srv"); err != nil || p.Enabled {
		t.Errorf("firewall_policy not cascaded on server delete: %+v, err=%v", p, err)
	}
}
