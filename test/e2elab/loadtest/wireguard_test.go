//go:build e2eload

package loadtest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn/wgfamily"
)

const wgTunnelSubnet = "10.80.0.0/24"

func TestLoadWireGuard(t *testing.T) {
	ctx := context.Background()
	sshClient := newSSHClient(t)
	p := wgfamily.New(wgfamily.Options{
		ProviderName: "wireguard", Interface: "wg0", ConfPath: "/etc/wireguard/wg0.conf",
		Binary: "wg", ServiceName: "wg-quick@wg0", PublicHost: serverIP, SSH: sshClient,
	})
	if err := p.EnsureServer(ctx, "10.80.0.1/24", 51820, "", ""); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	assertActive(t, ctx, sshClient, "wg-quick@wg0")

	st, err := p.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	for _, n := range concurrencyTiers() {
		n := n
		t.Run(fmt.Sprintf("concurrency=%d", n), func(t *testing.T) {
			r := loadWireGuardTier(t, ctx, sshClient, p, st.PublicKey, n)
			recordResult("wireguard", n, r)
		})
	}
}

func loadWireGuardTier(t *testing.T, ctx context.Context, sshClient *sshexec.Client, p *wgfamily.Provider, serverPub string, n int) tierResult {
	t.Helper()
	basePort := 15000
	var peerIDs []string
	var nss []string
	t.Cleanup(func() {
		for _, ns := range nss {
			delPeerNS(ns)
		}
		for _, id := range peerIDs {
			_ = p.RemovePeer(ctx, id)
		}
		_, _ = sshClient.Run(ctx, "pkill -f 'iperf3 -s' || true")
	})

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("wg-p%d", i)
		clientAddr := fmt.Sprintf("10.80.0.%d", 2+i)
		res, err := p.AddPeer(ctx, peerSpec(name, clientAddr+"/32"))
		if err != nil {
			t.Fatalf("AddPeer %d: %v", i, err)
		}
		peerIDs = append(peerIDs, res.Peer.PublicKey)

		ns := fmt.Sprintf("wg%d", i)
		newPeerNS(t, ns, i)
		nss = append(nss, ns)

		clientExecNS(t, ns, "ip link add wg0 type wireguard")
		writeStdin(t, ns, "wg0", res.PrivateKey)
		clientExecNS(t, ns, fmt.Sprintf(
			"wg set wg0 peer %s endpoint %s:51820 allowed-ips %s persistent-keepalive 15",
			serverPub, serverIP, wgTunnelSubnet))
		clientExecNS(t, ns, fmt.Sprintf("ip addr add %s/24 dev wg0", clientAddr))
		clientExecNS(t, ns, "ip link set wg0 up")

		port := basePort + i
		if _, err := sshClient.Run(ctx, fmt.Sprintf("iperf3 -s -p %d -B 10.80.0.1 -D", port)); err != nil {
			t.Fatalf("start iperf3 server %d: %v", i, err)
		}
	}

	// Let handshakes/keepalives settle before measuring.
	time.Sleep(2 * time.Second)

	// No RSS sample for WireGuard: it's an in-kernel implementation, no
	// userspace daemon process to read /proc/<pid>/status from -- CPU%
	// alone (from `docker stats`) is the meaningful number here.
	return runIperfTier(t, nss, "10.80.0.1", basePort, "")
}

// writeStdin pipes content to `wg set <iface> private-key /dev/stdin` inside
// netns ns -- avoids the private key ever touching a shell argv/log.
func writeStdin(t *testing.T, ns, iface, content string) {
	t.Helper()
	cmd := fmt.Sprintf("echo %s | ip netns exec %s wg set %s private-key /dev/stdin",
		shellSingleQuote(content), ns, iface)
	if out, err := runCmd("docker", "exec", clientContainer, "sh", "-c", cmd); err != nil {
		t.Fatalf("writeStdin ns=%s: %v: %s", ns, err, out)
	}
}
