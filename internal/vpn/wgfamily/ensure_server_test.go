package wgfamily

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// ensureFakeSSH is a dedicated fake for EnsureServer's tests: unlike
// fakeSSH (provider_test.go), it can represent "no config file yet" --
// ReadFile/`test -e` fail until WriteFile is called, mirroring a real host
// where a brand-new instance's conf genuinely doesn't exist.
type ensureFakeSSH struct {
	fileExists bool
	conf       string
	ran        []string
}

func (f *ensureFakeSSH) InterfaceExists(context.Context, string) bool { return f.fileExists }

func (f *ensureFakeSSH) ReadFile(context.Context, string) (string, error) {
	if !f.fileExists {
		return "", fmt.Errorf("no such file or directory")
	}
	return f.conf, nil
}

func (f *ensureFakeSSH) WriteFile(_ context.Context, _ string, content string) error {
	f.conf = content
	f.fileExists = true
	return nil
}

func (f *ensureFakeSSH) Run(_ context.Context, cmd string) (string, error) {
	f.ran = append(f.ran, cmd)
	if strings.HasPrefix(cmd, "test -e ") {
		if f.fileExists {
			return "", nil
		}
		return "", fmt.Errorf("exit status 1")
	}
	return "", nil
}

func ensureTestProvider(f *ensureFakeSSH) *Provider {
	return New(Options{
		ProviderName: "wireguard",
		Interface:    "wg0",
		ConfPath:     "/etc/wireguard/wg0.conf",
		Binary:       "wg",
		ServiceName:  "wg-quick@wg0",
		SSH:          f,
	})
}

func TestEnsureServerFreshBringUp(t *testing.T) {
	f := &ensureFakeSSH{}
	p := ensureTestProvider(f)

	if err := p.EnsureServer(context.Background(), "10.10.0.1/24", 51820, "1.1.1.1", "1420"); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	if !f.fileExists {
		t.Fatal("conf should exist after EnsureServer")
	}

	cf := ParseConf(f.conf)
	if addr, _ := cf.InterfaceGet("Address"); addr != "10.10.0.1/24" {
		t.Errorf("Address = %q, want 10.10.0.1/24", addr)
	}
	if port, _ := cf.InterfaceGet("ListenPort"); port != "51820" {
		t.Errorf("ListenPort = %q, want 51820", port)
	}
	if dns, _ := cf.InterfaceGet("DNS"); dns != "1.1.1.1" {
		t.Errorf("DNS = %q, want 1.1.1.1", dns)
	}
	if mtu, _ := cf.InterfaceGet("MTU"); mtu != "1420" {
		t.Errorf("MTU = %q, want 1420", mtu)
	}
	if priv, ok := cf.InterfaceGet("PrivateKey"); !ok || priv == "" {
		t.Error("expected a generated, non-empty PrivateKey")
	}

	foundEnable := false
	for _, cmd := range f.ran {
		if strings.Contains(cmd, "service enable wg-quick@wg0") {
			foundEnable = true
		}
	}
	if !foundEnable {
		t.Errorf("expected an installer 'service enable wg-quick@wg0' call, got commands: %v", f.ran)
	}
}

func TestEnsureServerNoopIfAlreadyConfigured(t *testing.T) {
	existing := "[Interface]\nPrivateKey = already-here\nAddress = 10.0.0.1/24\nListenPort = 51820\n"
	f := &ensureFakeSSH{fileExists: true, conf: existing}
	p := ensureTestProvider(f)

	// Different address/port than what's already configured -- must be
	// completely ignored, never applied, since a real WG interface with
	// live peers would break if Address/PrivateKey silently changed.
	if err := p.EnsureServer(context.Background(), "10.99.0.1/24", 12345, "8.8.8.8", "1300"); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	if f.conf != existing {
		t.Errorf("existing conf must be untouched, got:\n%s\nwant (unchanged):\n%s", f.conf, existing)
	}
	for _, cmd := range f.ran {
		if strings.Contains(cmd, "service enable") {
			t.Errorf("must not (re-)enable the service when already configured, got: %q", cmd)
		}
	}
}

func TestEnsureServerRequiresAddress(t *testing.T) {
	f := &ensureFakeSSH{}
	p := ensureTestProvider(f)
	if err := p.EnsureServer(context.Background(), "", 0, "", ""); err == nil {
		t.Error("expected an error when address is empty")
	}
	if f.fileExists {
		t.Error("must not write a conf file when address validation fails")
	}
}
