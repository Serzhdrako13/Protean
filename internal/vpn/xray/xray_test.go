package xray

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryHasAllStrategies(t *testing.T) {
	want := []string{
		"reality-vless-tcp", "vless-vision-tls", "vmess-ws-tls",
		"trojan-tcp-tls", "shadowsocks-2022", "vless-grpc-tls",
	}
	if len(All()) != len(want) {
		t.Fatalf("registry has %d strategies, want %d", len(All()), len(want))
	}
	for _, name := range want {
		if _, ok := Get(name); !ok {
			t.Errorf("strategy %q not registered", name)
		}
	}
}

func TestHelpers(t *testing.T) {
	u, err := NewUUID()
	if err != nil || len(u) != 36 {
		t.Fatalf("NewUUID = %q err=%v", u, err)
	}
	kp, err := GenRealityKeypair()
	if err != nil {
		t.Fatalf("GenRealityKeypair: %v", err)
	}
	for _, k := range []string{kp.PrivateKey, kp.PublicKey} {
		b, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil || len(b) != 32 {
			t.Errorf("reality key %q not 32 raw bytes: %v", k, err)
		}
	}
	sid, _ := NewShortID()
	if len(sid) != 16 {
		t.Errorf("shortId = %q", sid)
	}
}

func TestRealityInboundAndLink(t *testing.T) {
	kp, _ := GenRealityKeypair()
	uuid, _ := NewUUID()
	sid, _ := NewShortID()
	p := Params{
		pPort: "443", pSNI: "www.microsoft.com", pDest: "www.microsoft.com:443",
		pRealityPriv: kp.PrivateKey, pRealityPub: kp.PublicKey, pShortID: sid,
	}
	client := Client{Name: "alice", UUID: uuid}
	s, _ := Get("reality-vless-tcp")

	inb, err := s.BuildInbound(p, []Client{client})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}
	ss := inb["streamSettings"].(map[string]any)
	if ss["security"] != "reality" || ss["network"] != "tcp" {
		t.Errorf("streamSettings = %+v", ss)
	}
	clients := inb["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["id"] != uuid {
		t.Errorf("clients = %+v", clients)
	}
	if _, err := json.Marshal(inb); err != nil {
		t.Fatalf("inbound not JSON-serializable: %v", err)
	}

	link, err := s.ClientLink(p, client, "203.0.113.10")
	if err != nil {
		t.Fatalf("ClientLink: %v", err)
	}
	for _, want := range []string{"vless://", uuid + "@203.0.113.10:443", "security=reality", "pbk=" + kp.PublicKey, "#alice"} {
		if !strings.Contains(link, want) {
			t.Errorf("reality link missing %q\n%s", want, link)
		}
	}
}

func TestBuildInboundRequiresClientAndCrypto(t *testing.T) {
	s, _ := Get("reality-vless-tcp")
	base := Params{pSNI: "x", pDest: "x:443", pPort: "443", pRealityPriv: "k"}
	if _, err := s.BuildInbound(base, nil); err == nil {
		t.Error("expected error with no clients")
	}
	if _, err := s.BuildInbound(Params{pSNI: "x", pDest: "x:443", pPort: "443"}, []Client{{UUID: "u"}}); err == nil {
		t.Error("expected error without reality private key")
	}
}

func TestMultiClientInbound(t *testing.T) {
	s, _ := Get("vless-vision-tls")
	p := Params{pPort: "443", pDomain: "vpn.example.com"}
	u1, _ := NewUUID()
	u2, _ := NewUUID()
	inb, err := s.BuildInbound(p, []Client{{Name: "a", UUID: u1}, {Name: "b", UUID: u2}})
	if err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}
	clients := inb["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 2 {
		t.Fatalf("want 2 clients, got %d", len(clients))
	}
	if !s.MultiClient() {
		t.Error("vless-vision-tls should be multi-client")
	}
	if ss, _ := Get("shadowsocks-2022"); ss.MultiClient() {
		t.Error("shadowsocks-2022 should be single-client")
	}
}

func TestVMessLinkDecodes(t *testing.T) {
	uuid, _ := NewUUID()
	p := Params{pPort: "443", pDomain: "cdn.example.com", pWSPath: "/ws"}
	s, _ := Get("vmess-ws-tls")
	c := Client{Name: "phone", UUID: uuid}
	if _, err := s.BuildInbound(p, []Client{c}); err != nil {
		t.Fatalf("BuildInbound: %v", err)
	}
	link, err := s.ClientLink(p, c, "cdn.example.com")
	if err != nil {
		t.Fatalf("ClientLink: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatalf("vmess link not base64: %v", err)
	}
	var conf map[string]any
	if err := json.Unmarshal(b, &conf); err != nil {
		t.Fatalf("vmess payload not JSON: %v", err)
	}
	if conf["id"] != uuid || conf["net"] != "ws" || conf["tls"] != "tls" || conf["ps"] != "phone" {
		t.Errorf("vmess conf = %+v", conf)
	}
}

func TestTrojanAndShadowsocksLinks(t *testing.T) {
	pw, _ := NewPassword(16)

	tr, _ := Get("trojan-tcp-tls")
	tp := Params{pPort: "443", pDomain: "vpn.example.com"}
	tc := Client{Name: "t1", Password: pw}
	if _, err := tr.BuildInbound(tp, []Client{tc}); err != nil {
		t.Fatalf("trojan inbound: %v", err)
	}
	tl, _ := tr.ClientLink(tp, tc, "vpn.example.com")
	if !strings.HasPrefix(tl, "trojan://"+pw+"@vpn.example.com:443") || !strings.Contains(tl, "security=tls") {
		t.Errorf("trojan link = %s", tl)
	}

	ss, _ := Get("shadowsocks-2022")
	sp := Params{pPort: "8388"}
	sc := Client{Name: "s1", Password: pw}
	inb, err := ss.BuildInbound(sp, []Client{sc})
	if err != nil {
		t.Fatalf("ss inbound: %v", err)
	}
	if inb["protocol"] != "shadowsocks" {
		t.Errorf("ss protocol = %v", inb["protocol"])
	}
	sl, _ := ss.ClientLink(sp, sc, "203.0.113.10")
	if !strings.HasPrefix(sl, "ss://") || !strings.Contains(sl, "@203.0.113.10:8388") {
		t.Errorf("ss link = %s", sl)
	}
}

func TestGRPCAndVisionInbounds(t *testing.T) {
	uuid, _ := NewUUID()
	for _, name := range []string{"vless-grpc-tls", "vless-vision-tls"} {
		s, _ := Get(name)
		p := Params{pPort: "443", pDomain: "vpn.example.com"}
		inb, err := s.BuildInbound(p, []Client{{UUID: uuid}})
		if err != nil {
			t.Fatalf("%s inbound: %v", name, err)
		}
		if inb["streamSettings"].(map[string]any)["security"] != "tls" {
			t.Errorf("%s security not tls", name)
		}
		if _, err := json.Marshal(inb); err != nil {
			t.Errorf("%s not JSON: %v", name, err)
		}
		if _, err := s.ClientLink(p, Client{UUID: uuid}, "vpn.example.com"); err != nil {
			t.Errorf("%s link: %v", name, err)
		}
	}
}

func TestParamsListed(t *testing.T) {
	for _, s := range All() {
		if len(s.Params()) == 0 {
			t.Errorf("%s exposes no params", s.Name())
		}
		if s.Label() == "" {
			t.Errorf("%s has no label", s.Name())
		}
	}
}
