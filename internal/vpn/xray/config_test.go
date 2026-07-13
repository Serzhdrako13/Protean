package xray

import (
	"encoding/json"
	"testing"
)

func TestBuildServerConfigDirect(t *testing.T) {
	s, _ := Get("shadowsocks-2022")
	inb, _ := s.BuildInbound(Params{pPort: "8388"}, []Client{{Name: "c", Password: "pw"}})
	raw, err := BuildServerConfig([]map[string]any{inb}, nil)
	if err != nil {
		t.Fatalf("BuildServerConfig: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config not JSON: %v", err)
	}
	if _, ok := cfg["inbounds"]; !ok {
		t.Error("no inbounds")
	}
	// Direct egress: freedom present, no routing-to-relay.
	obs := cfg["outbounds"].([]any)
	if obs[0].(map[string]any)["protocol"] != "freedom" {
		t.Errorf("first outbound should be freedom, got %+v", obs[0])
	}
	if _, hasRouting := cfg["routing"]; hasRouting {
		t.Error("direct config should not route to a relay")
	}
}

func TestBuildServerConfigWithRelay(t *testing.T) {
	uuid, _ := NewUUID()
	kp, _ := GenRealityKeypair()
	relay, err := BuildRelayOutbound(RelaySpec{
		Strategy: "reality-vless-tcp", Host: "relay.abroad",
		Params: Params{pPort: "443", pUUID: uuid, pRealityPub: kp.PublicKey, pSNI: "www.microsoft.com", pShortID: "aabb"},
	})
	if err != nil {
		t.Fatalf("BuildRelayOutbound: %v", err)
	}
	s, _ := Get("vless-vision-tls")
	inb, _ := s.BuildInbound(Params{pPort: "443", pDomain: "hub.example.com"}, []Client{{UUID: uuid}})

	raw, err := BuildServerConfig([]map[string]any{inb}, []Outbound{relay})
	if err != nil {
		t.Fatalf("BuildServerConfig: %v", err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)

	obs := cfg["outbounds"].([]any)
	first := obs[0].(map[string]any)
	if first["protocol"] != "vless" || first["tag"] != "relay0" {
		t.Errorf("first outbound should be the tagged relay0, got %+v", first)
	}
	routing, ok := cfg["routing"].(map[string]any)
	if !ok {
		t.Fatal("relay config must have routing")
	}
	rules := routing["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != "relay0" {
		t.Errorf("routing must send traffic to relay0, got %+v", rules[0])
	}
	// relay vnext points at the foreign host.
	vnext := first["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
	if vnext["address"] != "relay.abroad" {
		t.Errorf("relay address = %v", vnext["address"])
	}
	// single-hop chain: no dialerProxy chaining into anything further.
	if ss, ok := first["streamSettings"].(map[string]any); ok {
		if _, hasSockopt := ss["sockopt"]; hasSockopt {
			t.Errorf("single-hop relay should not chain via sockopt.dialerProxy, got %+v", ss)
		}
	}
}

func TestBuildServerConfigWithRelayChain(t *testing.T) {
	uuid, _ := NewUUID()
	hop0, err := BuildRelayOutbound(RelaySpec{
		Strategy: "trojan-tcp-tls", Host: "relay0.abroad",
		Params: Params{pPort: "443", pPassword: "pw0", pDomain: "relay0.abroad"},
	})
	if err != nil {
		t.Fatalf("BuildRelayOutbound hop0: %v", err)
	}
	hop1, err := BuildRelayOutbound(RelaySpec{
		Strategy: "shadowsocks-2022", Host: "relay1.abroad",
		Params: Params{pPort: "8388", pPassword: "pw1"},
	})
	if err != nil {
		t.Fatalf("BuildRelayOutbound hop1: %v", err)
	}
	s, _ := Get("vless-vision-tls")
	inb, _ := s.BuildInbound(Params{pPort: "443", pDomain: "hub.example.com"}, []Client{{UUID: uuid}})

	raw, err := BuildServerConfig([]map[string]any{inb}, []Outbound{hop0, hop1})
	if err != nil {
		t.Fatalf("BuildServerConfig: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config not JSON: %v", err)
	}

	obs := cfg["outbounds"].([]any)
	first := obs[0].(map[string]any)
	second := obs[1].(map[string]any)
	if first["tag"] != "relay0" || second["tag"] != "relay1" {
		t.Errorf("chain tags wrong: %v / %v", first["tag"], second["tag"])
	}
	// hop0 must chain into hop1 via sockopt.dialerProxy; hop1 (last) must not chain further.
	ss0, ok := first["streamSettings"].(map[string]any)
	if !ok {
		t.Fatalf("hop0 missing streamSettings: %+v", first)
	}
	sockopt, ok := ss0["sockopt"].(map[string]any)
	if !ok || sockopt["dialerProxy"] != "relay1" {
		t.Errorf("hop0 should chain to relay1 via sockopt.dialerProxy, got %+v", ss0)
	}
	if ss1, ok := second["streamSettings"].(map[string]any); ok {
		if _, hasSockopt := ss1["sockopt"]; hasSockopt {
			t.Errorf("last hop should not chain further, got %+v", ss1)
		}
	}
	routing := cfg["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	if rules[0].(map[string]any)["outboundTag"] != "relay0" {
		t.Errorf("routing must send traffic to relay0 (first hop), got %+v", rules[0])
	}
}

func TestBuildRelayOutboundRejectsNonDialer(t *testing.T) {
	if _, err := BuildRelayOutbound(RelaySpec{Strategy: "vmess-ws-tls", Host: "x"}); err == nil {
		t.Error("vmess-ws-tls should not be offered as an egress relay dialer here")
	}
	if _, err := BuildRelayOutbound(RelaySpec{Strategy: "bogus", Host: "x"}); err == nil {
		t.Error("unknown strategy should error")
	}
}

func TestDecodeRelayChainBackwardCompat(t *testing.T) {
	// Pre-chaining rows stored a single RelaySpec JSON object, not an array.
	legacy := []byte(`{"Strategy":"trojan-tcp-tls","Host":"relay.abroad","Params":{"password":"pw"}}`)
	chain, err := decodeRelayChain(legacy)
	if err != nil {
		t.Fatalf("decodeRelayChain(legacy object): %v", err)
	}
	if len(chain) != 1 || chain[0].Host != "relay.abroad" || chain[0].Strategy != "trojan-tcp-tls" {
		t.Errorf("legacy decode = %+v", chain)
	}

	modern := []byte(`[{"Strategy":"trojan-tcp-tls","Host":"a"},{"Strategy":"shadowsocks-2022","Host":"b"}]`)
	chain, err = decodeRelayChain(modern)
	if err != nil {
		t.Fatalf("decodeRelayChain(array): %v", err)
	}
	if len(chain) != 2 || chain[0].Host != "a" || chain[1].Host != "b" {
		t.Errorf("array decode = %+v", chain)
	}

	empty := []byte(`{}`)
	chain, err = decodeRelayChain(empty)
	if err != nil {
		t.Fatalf("decodeRelayChain(empty object): %v", err)
	}
	if len(chain) != 0 {
		t.Errorf("empty object should decode to no hops, got %+v", chain)
	}
}
