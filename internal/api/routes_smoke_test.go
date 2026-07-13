package api

// Exercises route wiring and the auth middleware without a real database or
// SSH host: everything here short-circuits before touching s.store/s.auth.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"protean/internal/auth"
)

func newUnauthenticatedTestServer() *httptest.Server {
	// CSRF is exercised by the public /login route (sets a cookie), so the
	// server needs a real CSRF signer even without a DB or SSH backend.
	srv := &Server{csrf: auth.NewCSRF("test-secret")}
	return httptest.NewServer(srv.Routes())
}

func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Every page lives in the SPA now — there's no server-side auth gate on
// page routes: the SPA fallback serves the shell unconditionally and each
// page's own API calls 401/redirect client-side.
func TestSPAFallbackServesShellWithoutSession(t *testing.T) {
	ts := newUnauthenticatedTestServer()
	defer ts.Close()
	client := noRedirectClient()

	paths := []string{
		"/",
		"/providers/wireguard",
		"/providers/wireguard/status",
		"/providers/wireguard/peers/new",
		"/subnets",
	}
	for _, p := range paths {
		resp, err := client.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want %d (SPA shell)", p, resp.StatusCode, http.StatusOK)
		}
	}
}

func TestLoginPageIsPublic(t *testing.T) {
	ts := newUnauthenticatedTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatalf("GET /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /login: status = %d, want 200", resp.StatusCode)
	}
}
