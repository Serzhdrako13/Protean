package vpn

import (
	"context"
	"testing"
)

func TestParseHostInfo(t *testing.T) {
	const j = `{"os_family":"debian","pretty_name":"Ubuntu 24.04","pkg_manager":"apt","systemd":true,"selinux_enforcing":false,"supported":true,"providers":{"wireguard":{"installed":true,"installable":true},"amneziawg":{"installed":false,"installable":true},"openvpn":{"installed":false,"installable":true},"ikev2":{"installed":false,"installable":true}}}`

	info, err := ParseHostInfo(j)
	if err != nil {
		t.Fatalf("ParseHostInfo: %v", err)
	}
	if info.OSFamily != "debian" || info.PkgManager != "apt" || !info.Supported {
		t.Errorf("unexpected host info: %+v", info)
	}
	if !info.Providers["wireguard"].Installed {
		t.Error("wireguard should be installed")
	}
	if info.Providers["amneziawg"].Installed || !info.Providers["amneziawg"].Installable {
		t.Errorf("amneziawg should be installable but not installed: %+v", info.Providers["amneziawg"])
	}
}

func TestParseHostInfoError(t *testing.T) {
	if _, err := ParseHostInfo(`{"error":"cannot read /etc/os-release"}`); err == nil {
		t.Error("expected error when installer reports one")
	}
	if _, err := ParseHostInfo(`not json`); err == nil {
		t.Error("expected error on invalid JSON")
	}
}

type fakeInstallerSSH struct {
	out string
	err error
	cmd string
}

func (f *fakeInstallerSSH) Run(_ context.Context, cmd string) (string, error) {
	f.cmd = cmd
	return f.out, f.err
}

func TestInstallerInstallValidatesProvider(t *testing.T) {
	f := &fakeInstallerSSH{out: "[+] done"}
	inst := NewInstaller(f)

	if _, err := inst.Install(nil, "wireguard"); err != nil { //nolint:staticcheck // nil ctx ok in test
		t.Fatalf("Install: %v", err)
	}
	if f.cmd != "sudo "+InstallerPath+" install wireguard" {
		t.Errorf("unexpected command: %q", f.cmd)
	}

	if _, err := inst.Install(nil, "evil; rm -rf /"); err == nil { //nolint:staticcheck
		t.Error("expected rejection of invalid provider")
	}
}
