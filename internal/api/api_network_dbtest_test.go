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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
	"protean/internal/store"
	"protean/internal/vpn"
)

func networkTestDB(t *testing.T) *store.Store {
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

// failingIPForwardSSH fails exactly the ensure-ip-forward installer verb,
// succeeding on everything else -- simulates the real incident (a stale
// on-host installer script, or the sudoers gap fixed alongside this) where
// EnsureIPForward specifically errors while the rest of a mesh-settings
// save proceeds fine.
type failingIPForwardSSH struct{}

func (failingIPForwardSSH) Run(_ context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "ensure-ip-forward") {
		return "", errors.New("Process exited with status 1 (stderr: sudo: a password is required)")
	}
	return "", nil
}

// TestMeshSettingsUpdateSurfacesIPForwardFailure is the regression test
// for the real bug: before this fix, an EnsureIPForward failure was only
// slog.Error'd -- the HTTP response reported plain success while the
// feature's core precondition (traffic can't route between sites/egress
// without ip_forward) silently didn't hold.
func TestMeshSettingsUpdateSurfacesIPForwardFailure(t *testing.T) {
	st := networkTestDB(t)
	reg := vpn.NewRegistry()
	reg.Register(&updateTrackingProvider{name: "srv:wg0"})
	enc, err := auth.NewEncryptor(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	s := &Server{
		reg: reg, store: st, enc: enc,
		installerFor: func(string) (*vpn.Installer, bool) {
			return vpn.NewInstaller(failingIPForwardSSH{}), true
		},
	}

	req := httptest.NewRequest(http.MethodPut, "/api/providers/srv:wg0/mesh-settings",
		strings.NewReader(`{"mesh_enabled":true,"internet_egress":false}`))
	req.SetPathValue("provider", "srv:wg0")
	rec := httptest.NewRecorder()
	s.apiMeshSettingsUpdate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (partial-failure is reported in the envelope, not the HTTP status): body=%s", rec.Code, rec.Body.String())
	}
	env := decodeEnvelope(t, rec)
	if env.Success {
		t.Fatalf("expected Success=false when ensure_ip_forward fails, got envelope: %+v", env)
	}
	if !strings.Contains(env.Msg, "IPv4") && !strings.Contains(env.Msg, "форвардинг") {
		t.Errorf("error message should explain the ip_forward failure, got: %q", env.Msg)
	}

	// The setting itself must still have been persisted -- a host-side
	// hiccup enabling forwarding shouldn't roll back the admin's decision
	// to turn mesh on.
	ps, err := st.GetProviderSettings(context.Background(), "srv:wg0")
	if err != nil {
		t.Fatalf("GetProviderSettings: %v", err)
	}
	if !ps.MeshEnabled {
		t.Error("mesh_enabled should still be persisted despite the ip_forward failure")
	}
}

// serviceActionProvider is a minimal vpn.Provider that also implements
// vpn.ServiceNamed and vpn.ConfPermsRestorer, tracking whether
// RestoreConfPerms was called -- for asserting apiServiceAction's own
// conf-perms guard fires for the right set of actions.
type serviceActionProvider struct {
	updateTrackingProvider
	restoreCalled bool
	restoreErr    error
}

func (p *serviceActionProvider) ServiceName() string { return "wg-quick@wg0" }
func (p *serviceActionProvider) RestoreConfPerms(context.Context) error {
	p.restoreCalled = true
	return p.restoreErr
}

func doServiceAction(s *Server, provider, action string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/providers/"+provider+"/service",
		strings.NewReader(`{"action":"`+action+`"}`))
	req.SetPathValue("provider", provider)
	rec := httptest.NewRecorder()
	s.apiServiceAction(rec, req)
	return rec
}

// TestServiceActionRestoresConfPermsOnAnyStoppingAction is the regression
// test for the real bug: apiServiceAction only re-asserted conf
// permissions for the "restart" action, but scripts/protean-installer.sh's
// own cmd_service maps "disable" to `systemctl disable --now` (which also
// stops the unit, and therefore also triggers WireGuard's SaveConfig
// clobber), and a plain "stop" obviously does too. "start"/"enable" alone
// never stop an already-running unit, so they must NOT trigger it -- conf
// perms only need reasserting after the interface has actually restarted.
func TestServiceActionRestoresConfPermsOnAnyStoppingAction(t *testing.T) {
	st := networkTestDB(t)
	for _, tc := range []struct {
		action      string
		wantRestore bool
	}{
		{"restart", true},
		{"stop", true},
		{"disable", true},
		{"start", false},
		{"enable", false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			reg := vpn.NewRegistry()
			prov := &serviceActionProvider{updateTrackingProvider: updateTrackingProvider{name: "srv:wg0"}}
			reg.Register(prov)
			s := &Server{
				reg: reg, store: st,
				installerFor: func(string) (*vpn.Installer, bool) {
					return vpn.NewInstaller(failingIPForwardSSH{}), true // succeeds for "service ..." too
				},
			}
			rec := doServiceAction(s, "srv:wg0", tc.action)
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if prov.restoreCalled != tc.wantRestore {
				t.Errorf("action=%q: RestoreConfPerms called=%v, want %v", tc.action, prov.restoreCalled, tc.wantRestore)
			}
		})
	}
}
