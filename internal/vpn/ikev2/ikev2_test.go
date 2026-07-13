package ikev2

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
	"protean/internal/vpn/pki"
)

func TestRenderConnections(t *testing.T) {
	p := ServerParams{
		ConnName: "wgpanel", ServerID: "vpn.example.com", Pool: "10.9.0.0/24",
		DNS: []string{"10.9.0.1"}, LocalTS: []string{"192.168.5.0/24"},
		CACertFile: "ca.crt", ServerCert: "server.crt",
	}
	out := p.RenderConnections()
	for _, want := range []string{
		"connections {", "wgpanel {", "version = 2", "pools = wgpanel-pool",
		"certs = server.crt", "cacerts = ca.crt", "id = vpn.example.com",
		"local_ts = 192.168.5.0/24", "addrs = 10.9.0.0/24", "dns = 10.9.0.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("swanctl conf missing %q\n---\n%s", want, out)
		}
	}
}

func TestRenderConnectionsSiteClients(t *testing.T) {
	p := ServerParams{
		ConnName: "wgpanel", ServerID: "vpn.example.com", Pool: "10.9.0.0/24",
		LocalTS: []string{"192.168.5.0/24"}, CACertFile: "ca.crt", ServerCert: "server.crt",
		SiteClients: []SiteClient{
			{CN: "branch-office", Subnets: []string{"10.20.0.0/24", "10.21.0.0/24"}},
		},
	}
	out := p.RenderConnections()
	for _, want := range []string{
		"wgpanel-branch-office {", // dedicated conn
		"id = branch-office",      // matched on client cert CN
		"remote_ts = 10.20.0.0/24,10.21.0.0/24",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("site conf missing %q\n---\n%s", want, out)
		}
	}
	// Road-warrior base connection has no remote_ts.
	base := out[strings.Index(out, "wgpanel {"):strings.Index(out, "wgpanel-branch-office {")]
	if strings.Contains(base, "remote_ts") {
		t.Errorf("base road-warrior conn should not set remote_ts\n%s", base)
	}
}

func TestProfilesEmbedP12(t *testing.T) {
	p12 := []byte("PKCS12-BYTES")
	mc := mobileConfigParams{CN: "office-a", ServerID: "vpn.example.com", P12: p12, P12Pass: "pw"}.build()
	s := string(mc)
	for _, want := range []string{
		"com.apple.security.pkcs12", "com.apple.vpn.managed", "VPNType</key><string>IKEv2",
		"RemoteAddress</key><string>vpn.example.com", "LocalIdentifier</key><string>office-a",
		base64.StdEncoding.EncodeToString(p12),
	} {
		if !strings.Contains(s, want) {
			t.Errorf(".mobileconfig missing %q", want)
		}
	}

	ss, err := sswanProfile("office-a", "vpn.example.com", p12)
	if err != nil {
		t.Fatalf("sswanProfile: %v", err)
	}
	sj := string(ss)
	for _, want := range []string{`"type": "ikev2-cert"`, `"addr": "vpn.example.com"`, base64.StdEncoding.EncodeToString(p12)} {
		if !strings.Contains(sj, want) {
			t.Errorf(".sswan missing %q\n%s", want, sj)
		}
	}
}

func TestUUIDFromStable(t *testing.T) {
	if uuidFrom("x") != uuidFrom("x") {
		t.Error("uuidFrom must be deterministic")
	}
	if uuidFrom("a") == uuidFrom("b") {
		t.Error("different seeds should differ")
	}
	if len(uuidFrom("x")) != 36 {
		t.Errorf("bad UUID length: %q", uuidFrom("x"))
	}
}

func TestParseListSAs(t *testing.T) {
	const s = `wgpanel: #12, ESTABLISHED, IKEv2, spi ...
  local  'vpn.example.com' @ 203.0.113.10[4500]
  remote 'office-a' @ 198.51.100.9[4500]
wgpanel: #13, CONNECTING, IKEv2
  remote 'pending' @ 198.51.100.20[500]`

	sas := ParseListSAs(s)
	if len(sas) != 1 {
		t.Fatalf("got %d SAs, want 1 (only ESTABLISHED): %+v", len(sas), sas)
	}
	if sas[0].RemoteID != "office-a" {
		t.Errorf("RemoteID = %q", sas[0].RemoteID)
	}
	if !strings.HasPrefix(sas[0].Remote, "198.51.100.9") {
		t.Errorf("Remote = %q", sas[0].Remote)
	}
}

func TestBuildP12(t *testing.T) {
	ca, err := pki.NewInternalCA(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := ca.IssueClient("office-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := BuildP12(cc.CertPEM, cc.KeyPEM, ca.CACertPEM(), "s3cret")
	if err != nil {
		t.Fatalf("BuildP12: %v", err)
	}
	// Decode it back to prove it's a valid, password-protected bundle.
	key, cert, caCerts, err := pkcs12.DecodeChain(blob, "s3cret")
	if err != nil {
		t.Fatalf("decode p12: %v", err)
	}
	if key == nil || cert == nil || len(caCerts) != 1 {
		t.Errorf("p12 chain incomplete: key=%v cert=%v ca=%d", key != nil, cert != nil, len(caCerts))
	}
	if cert.Subject.CommonName != "office-a" {
		t.Errorf("cert CN = %q", cert.Subject.CommonName)
	}
	// Wrong password must fail.
	if _, _, _, err := pkcs12.DecodeChain(blob, "wrong"); err == nil {
		t.Error("decode with wrong password should fail")
	}
	_ = x509.Certificate{}
}
