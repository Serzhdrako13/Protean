package vpn

import (
	"context"
	"strings"
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

// sequencedInstallerSSH returns a scripted sequence of (out, err) pairs,
// one per call, and records every command it was asked to run -- for
// exercising the self-heal retry path (fails with "usage: ..." once,
// succeeds after a refresh).
type sequencedInstallerSSH struct {
	calls   []string
	results []struct {
		out string
		err error
	}
	i int
}

func (f *sequencedInstallerSSH) Run(_ context.Context, cmd string) (string, error) {
	f.calls = append(f.calls, cmd)
	if f.i >= len(f.results) {
		return "", nil
	}
	r := f.results[f.i]
	f.i++
	return r.out, r.err
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func TestInstallerSelfHealsOnUsageMismatch(t *testing.T) {
	f := &sequencedInstallerSSH{results: []struct {
		out string
		err error
	}{
		{err: usageError{"Process exited with status 2 (stderr: usage: " + InstallerPath + " {detect|install <provider>|...})"}},
		{}, // the refreshScript push
		{out: "ok"}, // the retried subnet-nat command succeeds
	}}
	inst := NewInstaller(f)

	if err := inst.SubnetNAT(nil, "add", "192.168.10.0/24"); err != nil { //nolint:staticcheck
		t.Fatalf("SubnetNAT: %v", err)
	}
	if len(f.calls) != 3 {
		t.Fatalf("expected 3 calls (fail, refresh, retry), got %d: %+v", len(f.calls), f.calls)
	}
	if f.calls[0] != "sudo "+InstallerPath+" subnet-nat add 192.168.10.0/24" {
		t.Errorf("call[0] = %q", f.calls[0])
	}
	if !strings.Contains(f.calls[1], "base64 -d | sudo tee "+InstallerPath) {
		t.Errorf("call[1] should push a fresh script, got %q", f.calls[1])
	}
	if f.calls[2] != "sudo "+InstallerPath+" subnet-nat add 192.168.10.0/24" {
		t.Errorf("call[2] (retry) = %q", f.calls[2])
	}
}

func TestSetPeerForwardRules(t *testing.T) {
	f := &fakeInstallerSSH{out: "ok"}
	inst := NewInstaller(f)

	if err := inst.SetPeerForwardRules(nil, "10.10.0.5", []string{"192.168.10.0/24", "192.168.20.5"}); err != nil { //nolint:staticcheck
		t.Fatalf("SetPeerForwardRules: %v", err)
	}
	want := "sudo " + InstallerPath + " peer-forward-rules 10.10.0.5/32 192.168.10.0/24,192.168.20.5/32"
	if f.cmd != want {
		t.Errorf("cmd = %q, want %q", f.cmd, want)
	}

	// Already-masked peer address and empty destination list (delete-only,
	// i.e. clear the restriction) are both passed through unmodified/bare.
	if err := inst.SetPeerForwardRules(nil, "10.10.0.5/32", nil); err != nil { //nolint:staticcheck
		t.Fatalf("SetPeerForwardRules (clear): %v", err)
	}
	if f.cmd != "sudo "+InstallerPath+" peer-forward-rules 10.10.0.5/32" {
		t.Errorf("clear cmd = %q", f.cmd)
	}

	if err := inst.SetPeerForwardRules(nil, "not-an-ip", nil); err == nil { //nolint:staticcheck
		t.Error("expected rejection of invalid peer address")
	}
	if err := inst.SetPeerForwardRules(nil, "10.10.0.5", []string{"evil; rm -rf /"}); err == nil { //nolint:staticcheck
		t.Error("expected rejection of invalid destination")
	}
}

func TestFixConfPerms(t *testing.T) {
	f := &fakeInstallerSSH{out: "ok"}
	inst := NewInstaller(f)

	if err := inst.FixConfPerms(nil, "/etc/wireguard/wg0.conf"); err != nil { //nolint:staticcheck
		t.Fatalf("FixConfPerms: %v", err)
	}
	// fakeInstallerSSH doesn't implement User() -- must fall back to
	// "protean" (setup-host.sh's own PANEL_USER), not send no owner at all.
	want := "sudo " + InstallerPath + " fix-conf-perms /etc/wireguard/wg0.conf protean"
	if f.cmd != want {
		t.Errorf("cmd = %q, want %q", f.cmd, want)
	}

	if err := inst.FixConfPerms(nil, "/etc/amnezia/amneziawg/awg0.conf"); err != nil { //nolint:staticcheck
		t.Fatalf("FixConfPerms (amneziawg): %v", err)
	}

	for _, bad := range []string{
		"/etc/passwd",
		"/etc/wireguard/../passwd",
		"/etc/wireguard/wg0.conf; rm -rf /",
		"/etc/openvpn/server.conf",
		"relative/wg0.conf",
	} {
		if err := inst.FixConfPerms(nil, bad); err == nil { //nolint:staticcheck
			t.Errorf("expected rejection of path %q", bad)
		}
	}
}

// fakeInstallerSSHWithUser additionally implements User(), simulating
// sshexec.Client's real SSH-username accessor -- FixConfPerms needs this
// to chown a conf file back to a custom (admin-chosen) service account
// name on a host provisioned via BootstrapHost's owner-based model,
// rather than always assuming "protean".
type fakeInstallerSSHWithUser struct {
	fakeInstallerSSH
	user string
}

func (f *fakeInstallerSSHWithUser) User() string { return f.user }

func TestFixConfPermsUsesRealSSHUser(t *testing.T) {
	f := &fakeInstallerSSHWithUser{fakeInstallerSSH: fakeInstallerSSH{out: "ok"}, user: "custom-svc"}
	inst := NewInstaller(f)

	if err := inst.FixConfPerms(nil, "/etc/wireguard/wg0.conf"); err != nil { //nolint:staticcheck
		t.Fatalf("FixConfPerms: %v", err)
	}
	want := "sudo " + InstallerPath + " fix-conf-perms /etc/wireguard/wg0.conf custom-svc"
	if f.cmd != want {
		t.Errorf("cmd = %q, want %q", f.cmd, want)
	}

	// A malicious/malformed SSH username must never reach the shell.
	f.user = "custom-svc; rm -rf /"
	if err := inst.FixConfPerms(nil, "/etc/wireguard/wg0.conf"); err == nil { //nolint:staticcheck
		t.Error("expected rejection of an invalid SSH username")
	}
}

func TestInstallerNoSelfHealOnOtherErrors(t *testing.T) {
	f := &sequencedInstallerSSH{results: []struct {
		out string
		err error
	}{
		{err: usageError{"Process exited with status 1 (stderr: some real iptables failure)"}},
	}}
	inst := NewInstaller(f)

	if err := inst.SubnetNAT(nil, "add", "192.168.10.0/24"); err == nil { //nolint:staticcheck
		t.Fatal("expected the real error to propagate")
	}
	if len(f.calls) != 1 {
		t.Fatalf("a non-\"usage:\" error must not trigger a refresh+retry, got %d calls: %+v", len(f.calls), f.calls)
	}
}
