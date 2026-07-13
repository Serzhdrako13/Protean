package api

import (
	"strings"
	"testing"

	"protean/internal/store"
)

func TestPeerEventMsgContentToggles(t *testing.T) {
	s := &Server{}
	meta := peerMeta{name: "office-a", endpoint: "198.51.100.9:44321", address: "10.8.0.2/32", known: true}

	// Minimal: category + peer + verb.
	min := s.peerEventMsg(store.NotifySettings{}, "wg0", "PK", "connected", "client", meta)
	if min != `client peer "office-a" connected` {
		t.Errorf("minimal msg = %q", min)
	}

	// Full: provider + address + endpoint.
	full := s.peerEventMsg(store.NotifySettings{
		CtntProvider: true, CtntEndpoint: true, CtntAddress: true,
	}, "wg0", "PK", "connected", "site", meta)
	for _, want := range []string{"wg0:", "site peer", `"office-a"`, "10.8.0.2/32", "198.51.100.9:44321"} {
		if !strings.Contains(full, want) {
			t.Errorf("full msg %q missing %q", full, want)
		}
	}

	// Falls back to the key when no friendly name.
	noname := s.peerEventMsg(store.NotifySettings{}, "wg0", "PUBKEY", "disconnected", "client", peerMeta{})
	if !strings.Contains(noname, `"PUBKEY"`) {
		t.Errorf("expected pubkey fallback, got %q", noname)
	}
}

func TestCategoryEventFlags(t *testing.T) {
	st := store.NotifySettings{EvSiteDisconnect: true, EvClientConnect: true}
	if !disconnectEnabled(st, "site") || disconnectEnabled(st, "client") {
		t.Error("site disconnect on, client disconnect off expected")
	}
	if !connectEnabled(st, "client") || connectEnabled(st, "site") {
		t.Error("client connect on, site connect off expected")
	}
}
