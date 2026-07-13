//go:build integration

// Integration test against a real WireGuard interface in a throwaway network
// namespace. Excluded from normal builds (needs the `integration` tag) and
// skips unless run as root on a host with `wg`/`ip` and PROTEAN_INTEGRATION=1.
//
//	sudo PROTEAN_INTEGRATION=1 go test -tags integration ./internal/vpn/wgfamily/ -run Integration -v
package wgfamily

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"protean/internal/vpn"
)

const testNS = "wgpaneltest"

// localRunner satisfies SSHRunner by executing commands locally inside the
// test network namespace, and file ops directly on the host filesystem.
type localRunner struct{ ns string }

func (l localRunner) Run(_ context.Context, cmd string) (string, error) {
	cmd = strings.TrimPrefix(cmd, "sudo ")
	full := fmt.Sprintf("ip netns exec %s sh -c %s", l.ns, shellSingleQuote(cmd))
	out, err := exec.Command("sh", "-c", full).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}
	return string(out), nil
}
func (l localRunner) ReadFile(_ context.Context, path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
func (l localRunner) WriteFile(_ context.Context, path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
func (l localRunner) InterfaceExists(ctx context.Context, iface string) bool {
	_, err := l.Run(ctx, "ip link show "+iface)
	return err == nil
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func mustRun(t *testing.T, cmd string) {
	t.Helper()
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("cmd %q: %v: %s", cmd, err, out)
	}
}

func TestIntegrationWireGuardLifecycle(t *testing.T) {
	if os.Getenv("PROTEAN_INTEGRATION") != "1" {
		t.Skip("set PROTEAN_INTEGRATION=1 to run")
	}
	if os.Geteuid() != 0 {
		t.Skip("must run as root")
	}
	for _, bin := range []string{"wg", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found", bin)
		}
	}

	// Namespace + interface teardown/setup.
	_ = exec.Command("ip", "netns", "del", testNS).Run()
	mustRun(t, "ip netns add "+testNS)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", testNS).Run() })

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	_ = pub

	confDir := t.TempDir()
	confPath := filepath.Join(confDir, "wg0.conf")
	conf := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.99.0.1/24\nListenPort = 51899\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	// Bring up wg0 inside the namespace from that key.
	mustRun(t, "ip netns exec "+testNS+" ip link add wg0 type wireguard")
	var keyBuf bytes.Buffer
	keyBuf.WriteString(priv)
	cmd := exec.Command("sh", "-c", "ip netns exec "+testNS+" wg set wg0 private-key /dev/stdin listen-port 51899")
	cmd.Stdin = &keyBuf
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wg set: %v: %s", err, out)
	}
	mustRun(t, "ip netns exec "+testNS+" ip addr add 10.99.0.1/24 dev wg0")
	mustRun(t, "ip netns exec "+testNS+" ip link set wg0 up")

	p := New(Options{
		ProviderName: "wireguard", Interface: "wg0", ConfPath: confPath,
		Binary: "wg", ServiceName: "wg-quick@wg0", SSH: localRunner{ns: testNS},
	})
	ctx := context.Background()

	// Status
	st, err := p.Status(ctx)
	if err != nil || !st.Up {
		t.Fatalf("Status up=%v err=%v", st.Up, err)
	}
	if st.Address != "10.99.0.1/24" {
		t.Errorf("Address = %q", st.Address)
	}

	// AddPeer -> appears live and in conf
	res, err := p.AddPeer(ctx, vpn.PeerSpec{Name: "client-a", AllowedIPs: []string{"10.99.0.2/32"}})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	peers, err := p.ListPeers(ctx)
	if err != nil || len(peers) != 1 || peers[0].PublicKey != res.Peer.PublicKey {
		t.Fatalf("ListPeers after add = %+v err=%v", peers, err)
	}
	if !strings.Contains(mustReadFile(t, confPath), res.Peer.PublicKey) {
		t.Error("new peer not persisted in conf")
	}

	// RemovePeer -> gone live
	if err := p.RemovePeer(ctx, res.Peer.PublicKey); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	peers, err = p.ListPeers(ctx)
	if err != nil || len(peers) != 0 {
		t.Fatalf("ListPeers after remove = %+v err=%v", peers, err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
