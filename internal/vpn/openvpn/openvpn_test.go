package openvpn

import (
	"strings"
	"testing"
	"time"
)

func TestParseStatusV2(t *testing.T) {
	const s = `TITLE,OpenVPN 2.6.0
TIME,2026-07-06 10:00:00,1751792400
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
CLIENT_LIST,office-a,203.0.113.5:51820,10.8.0.2,,123456,654321,2026-07-06 09:00:00,1751788800,UNDEF,1,0,AES-256-GCM
CLIENT_LIST,laptop,198.51.100.9:44321,10.8.0.3,,10,20,2026-07-06 09:30:00,1751790600,UNDEF,2,1,AES-256-GCM
ROUTING_TABLE,...
GLOBAL_STATS,Max bcast/mcast queue length,0
END`

	clients := ParseStatus(s)
	if len(clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(clients))
	}
	a := clients[0]
	if a.CommonName != "office-a" || a.RealAddress != "203.0.113.5:51820" || a.VirtualAddress != "10.8.0.2" {
		t.Errorf("client[0] = %+v", a)
	}
	if a.BytesReceived != 123456 || a.BytesSent != 654321 {
		t.Errorf("client[0] bytes = %d/%d", a.BytesReceived, a.BytesSent)
	}
	if !a.ConnectedSince.Equal(time.Unix(1751788800, 0)) {
		t.Errorf("client[0] since = %v", a.ConnectedSince)
	}
}

func TestParseStatusV3Tab(t *testing.T) {
	s := "CLIENT_LIST\toffice-b\t203.0.113.7:1194\t10.8.0.4\t\t5\t6\t2026-07-06 09:00:00\t1751788800\tUNDEF\t3\t2\tAES-256-GCM"
	clients := ParseStatus(s)
	if len(clients) != 1 || clients[0].CommonName != "office-b" || clients[0].VirtualAddress != "10.8.0.4" {
		t.Fatalf("v3 parse failed: %+v", clients)
	}
}

func TestServerConfRender(t *testing.T) {
	p := ServerParams{
		Port: 1194, ServerNet: "10.8.0.0", ServerMask: "255.255.255.0",
		CACertPath: "/etc/openvpn/server/ca.crt", ServerCert: "/etc/openvpn/server/server.crt",
		ServerKey: "/etc/openvpn/server/server.key", TLSCryptKey: "/etc/openvpn/server/tc.key",
		ClientConfigDir: "/etc/openvpn/server/ccd", StatusPath: "/run/openvpn-server/status.log",
		CRLPath: "/etc/openvpn/server/crl.pem",
		DNS:     []string{"10.8.0.1"}, PushRoutes: []string{"192.168.5.0/24"}, RedirectGateway: true,
		TunMTU: 1400, Mssfix: 1350,
	}
	out := p.Render()
	for _, want := range []string{
		"port 1194", "proto udp", "topology subnet",
		"server 10.8.0.0 255.255.255.0", "tls-crypt /etc/openvpn/server/tc.key",
		"crl-verify /etc/openvpn/server/crl.pem",
		"client-config-dir /etc/openvpn/server/ccd", "status /run/openvpn-server/status.log",
		`push "dhcp-option DNS 10.8.0.1"`, `push "redirect-gateway def1 bypass-dhcp"`,
		`push "route 192.168.5.0 255.255.255.0"`,
		"tun-mtu 1400", "mssfix 1350",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("server conf missing %q\n---\n%s", want, out)
		}
	}
}

func TestServerConfRenderOmitsMTUWhenUnset(t *testing.T) {
	out := ServerParams{Port: 1194, ServerNet: "10.8.0.0", ServerMask: "255.255.255.0"}.Render()
	if strings.Contains(out, "tun-mtu") || strings.Contains(out, "mssfix") {
		t.Errorf("expected no tun-mtu/mssfix line when unset\n%s", out)
	}
}

func TestBundleBuild(t *testing.T) {
	b := BundleParams{
		RemoteHost: "vpn.example.com", RemotePort: 1194, Proto: "udp",
		CACertPEM: "CA-PEM", ClientCertPEM: "CERT-PEM", ClientKeyPEM: "KEY-PEM", TLSCryptPEM: "TC-PEM",
		TunMTU: 1400, Mssfix: 1350,
	}.Build()
	for _, want := range []string{
		"client", "remote vpn.example.com 1194", "remote-cert-tls server",
		"<ca>\nCA-PEM\n</ca>", "<cert>\nCERT-PEM\n</cert>", "<key>\nKEY-PEM\n</key>", "<tls-crypt>\nTC-PEM\n</tls-crypt>",
		"tun-mtu 1400", "mssfix 1350",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("bundle missing %q\n---\n%s", want, b)
		}
	}
}

func TestBundleOmitsKeyWhenCSRBased(t *testing.T) {
	b := BundleParams{
		RemoteHost: "vpn.example.com", RemotePort: 1194,
		CACertPEM: "CA", ClientCertPEM: "CERT", ClientKeyPEM: "", TLSCryptPEM: "TC",
	}.Build()
	if strings.Contains(b, "<key>") {
		t.Errorf("CSR-based bundle must not inline a <key> block\n%s", b)
	}
	if !strings.Contains(b, "key /path/to/your.key") {
		t.Errorf("CSR-based bundle should note the client supplies its own key\n%s", b)
	}
}

func TestCIDRToNetMask(t *testing.T) {
	n, m, ok := cidrToNetMask("10.8.0.0/24")
	if !ok || n != "10.8.0.0" || m != "255.255.255.0" {
		t.Errorf("got %q %q %v", n, m, ok)
	}
	if _, _, ok := cidrToNetMask("2001:db8::/64"); ok {
		t.Error("IPv6 should return ok=false here")
	}
}
