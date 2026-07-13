//go:build dbtest

package api

import (
	"net/http/httptest"
	"testing"

	"protean/internal/store"
	"protean/internal/vpn"
)

func TestValidateWGFamilyCreateAddressOverlap(t *testing.T) {
	st := nodesTestDB(t)
	ctx := httptest.NewRequest("GET", "/", nil).Context()
	if err := st.CreateServer(ctx, store.Server{ID: "srv1", Host: "10.0.0.1", SSHUser: "root", EncKeyPEM: []byte("x")}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	reg := vpn.NewRegistry()
	reg.Register(&nodeFakeWGProvider{name: "srv1:wg0", address: "10.10.0.1/24"})
	s := newNodesTestServer(t, st, reg)

	req := httptest.NewRequest("POST", "/api/servers/srv1/instances", nil)

	// Overlapping candidate: rejected.
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{"address": "10.10.0.5/24"}); err == nil {
		t.Error("expected overlap error for an address inside the existing tunnel's subnet")
	}
	// Distinct subnet: accepted.
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{"address": "10.20.0.1/24"}); err != nil {
		t.Errorf("expected non-overlapping address to pass, got: %v", err)
	}
	// No address at all: rejected (required for wg-family).
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{}); err == nil {
		t.Error("expected an error when address is missing")
	}
}

func TestValidateWGFamilyCreatePortCollision(t *testing.T) {
	st := nodesTestDB(t)
	ctx := httptest.NewRequest("GET", "/", nil).Context()
	if err := st.CreateServer(ctx, store.Server{ID: "srv1", Host: "10.0.0.1", SSHUser: "root", EncKeyPEM: []byte("x")}); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := st.CreateServerInstance(ctx, store.ServerInstance{
		ServerID: "srv1", LocalName: "wg0", Type: "wireguard",
		Config: map[string]string{"listen_port": "51820"},
	}); err != nil {
		t.Fatalf("CreateServerInstance: %v", err)
	}

	reg := vpn.NewRegistry() // empty -- overlap check only cares about live tunnel CIDRs, none registered here
	s := newNodesTestServer(t, st, reg)
	req := httptest.NewRequest("POST", "/api/servers/srv1/instances", nil)

	// Same port, same server: rejected.
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{"address": "10.30.0.1/24", "listen_port": "51820"}); err == nil {
		t.Error("expected a port-collision error for a duplicate listen_port on the same server")
	}
	// Different port: accepted.
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{"address": "10.30.0.1/24", "listen_port": "51821"}); err != nil {
		t.Errorf("expected a distinct listen_port to pass, got: %v", err)
	}
	// No port at all (wg assigns one at runtime): accepted, never collides.
	if err := s.validateWGFamilyCreate(req, "srv1", map[string]string{"address": "10.30.0.1/24"}); err != nil {
		t.Errorf("expected an unset listen_port to pass, got: %v", err)
	}
}
