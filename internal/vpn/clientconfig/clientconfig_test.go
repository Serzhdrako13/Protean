package clientconfig

import (
	"strings"
	"testing"
)

func TestBuild(t *testing.T) {
	text := Build(Params{
		ClientPrivateKey:    "clientpriv",
		ClientAddress:       "10.10.0.5/32",
		DNS:                 "10.10.0.1",
		ServerPublicKey:     "serverpub",
		Endpoint:            "203.0.113.10:51820",
		AllowedIPs:          []string{"10.10.0.0/24", "192.168.1.0/24"},
		PersistentKeepalive: 25,
	})

	want := "[Interface]\n" +
		"PrivateKey = clientpriv\n" +
		"Address = 10.10.0.5/32\n" +
		"DNS = 10.10.0.1\n" +
		"\n[Peer]\n" +
		"PublicKey = serverpub\n" +
		"Endpoint = 203.0.113.10:51820\n" +
		"AllowedIPs = 10.10.0.0/24, 192.168.1.0/24\n" +
		"PersistentKeepalive = 25\n"

	if text != want {
		t.Errorf("Build() =\n%s\nwant\n%s", text, want)
	}
}

func TestBuildOmitsOptionalFields(t *testing.T) {
	text := Build(Params{
		ClientPrivateKey: "clientpriv",
		ClientAddress:    "10.10.0.5/32",
		ServerPublicKey:  "serverpub",
		Endpoint:         "203.0.113.10:51820",
		AllowedIPs:       []string{"10.10.0.0/24"},
	})

	if strings.Contains(text, "DNS") {
		t.Error("expected no DNS line when DNS is empty")
	}
	if strings.Contains(text, "MTU") {
		t.Error("expected no MTU line when MTU is 0")
	}
	if strings.Contains(text, "PersistentKeepalive") {
		t.Error("expected no PersistentKeepalive line when 0")
	}
}

func TestBuildIncludesMTU(t *testing.T) {
	text := Build(Params{
		ClientPrivateKey: "clientpriv",
		ClientAddress:    "10.10.0.5/32",
		MTU:              1280,
		ServerPublicKey:  "serverpub",
		Endpoint:         "203.0.113.10:51820",
		AllowedIPs:       []string{"10.10.0.0/24"},
	})
	if !strings.Contains(text, "MTU = 1280\n") {
		t.Errorf("expected MTU line, got:\n%s", text)
	}
}

func TestQRPNG(t *testing.T) {
	png, err := QRPNG("hello world")
	if err != nil {
		t.Fatalf("QRPNG: %v", err)
	}
	if len(png) == 0 {
		t.Error("QRPNG returned empty PNG")
	}
}
