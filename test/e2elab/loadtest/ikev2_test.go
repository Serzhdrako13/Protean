//go:build e2eload

package loadtest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn/ikev2"
)

type ikev2Client struct {
	cert, p12pass, addr, subnets string
	encKey                       []byte
}

type fakeIKEv2Store struct {
	mu      sync.Mutex
	caCert  string
	caKey   []byte
	clients map[string]ikev2Client
	revoked []ikev2.RevokedCert
	crlNum  int64
}

func newFakeIKEv2Store() *fakeIKEv2Store { return &fakeIKEv2Store{clients: map[string]ikev2Client{}} }

func (s *fakeIKEv2Store) GetCAMaterial(context.Context, string) (string, []byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caCert == "" {
		return "", nil, "", fmt.Errorf("none")
	}
	return s.caCert, s.caKey, "internal", nil
}
func (s *fakeIKEv2Store) SaveCAMaterial(_ context.Context, _, cert string, key []byte, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCert, s.caKey = cert, key
	return nil
}
func (s *fakeIKEv2Store) SaveClient(_ context.Context, _, cn, cert string, key []byte, p12pass, addr, subnets string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[cn] = ikev2Client{cert: cert, encKey: key, p12pass: p12pass, addr: addr, subnets: subnets}
	return nil
}
func (s *fakeIKEv2Store) GetClient(_ context.Context, _, cn string) (string, []byte, string, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[cn]
	if !ok {
		return "", nil, "", "", "", fmt.Errorf("not found")
	}
	return c.cert, c.encKey, c.p12pass, c.addr, c.subnets, nil
}
func (s *fakeIKEv2Store) ListClients(context.Context, string) ([]string, []string, []string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cns, addrs, subs, pass []string
	for cn, c := range s.clients {
		cns = append(cns, cn)
		addrs = append(addrs, c.addr)
		subs = append(subs, c.subnets)
		pass = append(pass, c.p12pass)
	}
	return cns, addrs, subs, pass, nil
}
func (s *fakeIKEv2Store) DeleteClient(_ context.Context, _, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, cn)
	return nil
}
func (s *fakeIKEv2Store) AddRevokedCert(_ context.Context, _, serial, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, ikev2.RevokedCert{Serial: serial, RevokedAt: time.Now()})
	return nil
}
func (s *fakeIKEv2Store) ListRevokedCerts(context.Context, string) ([]ikev2.RevokedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked, nil
}
func (s *fakeIKEv2Store) NextCRLNumber(context.Context, string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlNum++
	return s.crlNum, nil
}
func (s *fakeIKEv2Store) SaveServerRoutes(context.Context, string, []string, bool) error { return nil }
func (s *fakeIKEv2Store) GetServerRoutes(context.Context, string) ([]string, bool, bool, error) {
	return nil, false, true, nil
}

// TestLoadIKEv2 runs N concurrent real IKE_SAs from a SINGLE shared charon
// daemon in the client container's root network namespace -- unlike the
// other three protocols, IKEv2 doesn't need a netns per simulated peer:
// strongSwan natively supports many simultaneous connections, each
// authenticated with its own certificate, from one daemon (exactly how one
// real machine can run several IPsec profiles at once). What matters for
// load-testing the SERVER is N genuine concurrent IKE_SAs/child SAs with
// real ESP traffic -- confirmed live that a single daemon delivers exactly
// that, and multi-netns-multi-charon (distinct VICI sockets, mount
// namespaces per instance) turned out to be unnecessary complexity for
// what this measures.
func TestLoadIKEv2(t *testing.T) {
	ctx := context.Background()
	sshClient := newSSHClient(t)
	store := newFakeIKEv2Store()
	p := ikev2.New(ikev2.Options{
		Instance: "loadtest:ikev2", ConnName: "loadtest", SwanctlDir: "/etc/swanctl",
		ServiceName: "ipsec", ServerID: serverIP, Pool: "10.9.0.0/24",
		SSH: sshClient, Store: store, Enc: fakeSealer{},
	})
	if err := p.EnsureServer(ctx, nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	assertActive(t, ctx, sshClient, "ipsec")

	if _, err := runCmd("docker", "exec", "-d", clientContainer, "/usr/lib/ipsec/charon"); err != nil {
		t.Fatalf("start charon: %v", err)
	}
	waitForVICI(t)

	caCert := store.caCert
	clientWriteFile(t, "/etc/swanctl/x509ca/loadtest-ca.pem", caCert)

	for _, n := range concurrencyTiers() {
		n := n
		t.Run(fmt.Sprintf("concurrency=%d", n), func(t *testing.T) {
			r := loadIKEv2Tier(t, ctx, sshClient, p, store, n)
			recordResult("ikev2", n, r)
		})
	}
}

func waitForVICI(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := clientExecErr("test -S /run/charon.vici"); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("charon VICI socket never appeared")
}

func loadIKEv2Tier(t *testing.T, ctx context.Context, sshClient *sshexec.Client, p *ikev2.Provider, store *fakeIKEv2Store, n int) tierResult {
	t.Helper()
	var peerIDs []string
	var connNames []string
	t.Cleanup(func() {
		for _, conn := range connNames {
			_, _ = clientExecErr("swanctl --terminate --ike " + conn)
		}
		clientExec(t, "rm -f /etc/swanctl/conf.d/loadtest.conf")
		for i := range peerIDs {
			clientExec(t, fmt.Sprintf("rm -f /etc/swanctl/x509/lt%d.pem /etc/swanctl/private/lt%d.key", i, i))
		}
		clientExec(t, "swanctl --load-all >/dev/null 2>&1 || true")
		for _, id := range peerIDs {
			_ = p.RemovePeer(ctx, id)
		}
		_, _ = sshClient.Run(ctx, "pkill -f 'iperf3 -s' || true")
	})

	basePort := 15200
	var b strings.Builder
	b.WriteString("connections {\n")
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("ikev2-p%d", i)
		res, err := p.AddPeer(ctx, peerSpec(name))
		if err != nil {
			t.Fatalf("AddPeer %d: %v", i, err)
		}
		peerIDs = append(peerIDs, res.Peer.ID)

		cert, encKey, _, _, _, err := store.GetClient(ctx, "loadtest:ikev2", name)
		if err != nil {
			t.Fatalf("GetClient %d: %v", i, err)
		}
		certPath := fmt.Sprintf("/etc/swanctl/x509/lt%d.pem", i)
		keyPath := fmt.Sprintf("/etc/swanctl/private/lt%d.key", i)
		clientWriteFile(t, certPath, cert)
		clientWriteFile(t, keyPath, string(encKey))

		connName := fmt.Sprintf("lt%d", i)
		connNames = append(connNames, connName)
		fmt.Fprintf(&b, "   %s {\n", connName)
		b.WriteString("      version = 2\n")
		// Server requires a virtual IP via config payload (confirmed
		// live: "received FAILED_CP_REQUIRED notify, no CHILD_SA built"
		// without this) -- 0.0.0.0 requests any address from the
		// server's pool rather than pinning a specific one.
		b.WriteString("      vips = 0.0.0.0\n")
		fmt.Fprintf(&b, "      remote_addrs = %s\n", serverIP)
		b.WriteString("      local {\n")
		b.WriteString("         auth = pubkey\n")
		fmt.Fprintf(&b, "         certs = %s\n", certPath)
		b.WriteString("      }\n")
		b.WriteString("      remote {\n")
		b.WriteString("         auth = pubkey\n")
		fmt.Fprintf(&b, "         id = %s\n", serverIP)
		b.WriteString("         cacerts = /etc/swanctl/x509ca/loadtest-ca.pem\n")
		b.WriteString("      }\n")
		b.WriteString("      children {\n")
		b.WriteString("         net {\n")
		b.WriteString("            remote_ts = 0.0.0.0/0\n")
		b.WriteString("            esp_proposals = aes256-sha256-modp2048\n")
		b.WriteString("            start_action = none\n")
		b.WriteString("         }\n")
		b.WriteString("      }\n")
		b.WriteString("      proposals = aes256-sha256-modp2048\n")
		b.WriteString("   }\n")

		port := basePort + i
		if _, err := sshClient.Run(ctx, fmt.Sprintf("iperf3 -s -p %d -D", port)); err != nil {
			t.Fatalf("start iperf3 server %d: %v", i, err)
		}
	}
	b.WriteString("}\n")
	clientWriteFile(t, "/etc/swanctl/conf.d/loadtest.conf", b.String())

	clientExec(t, "swanctl --load-all")

	for _, conn := range connNames {
		if _, err := clientExecErr("swanctl --initiate --child net --ike " + conn); err != nil {
			t.Logf("initiate %s: %v", conn, err)
		}
	}

	time.Sleep(time.Duration(2+n/10) * time.Second)

	// Discover each connection's assigned local virtual IP (the source
	// address iperf3 needs to bind to route through that specific SA) from
	// swanctl's own SA listing rather than assuming a numbering scheme.
	saOut := clientExec(t, "swanctl --list-sas")
	localIPs := parseSwanctlLocalVIPs(saOut, connNames)

	resCh := make(chan iperfClientResult, n)
	var wg sync.WaitGroup
	for i, conn := range connNames {
		i, conn := i, conn
		vip, ok := localIPs[conn]
		if !ok {
			resCh <- iperfClientResult{err: fmt.Errorf("conn %s: no established SA / virtual IP found", conn)}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := basePort + i
			out, err := clientExecErr(fmt.Sprintf("iperf3 -c %s -p %d -B %s -t 6 -J", serverIP, port, vip))
			if err != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("conn=%s: %w", conn, err)}
				return
			}
			mbps, perr := parseIperfSentMbps(out)
			if perr != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("conn=%s parse: %w", conn, perr)}
				return
			}
			resCh <- iperfClientResult{mbps: mbps}
		}()
	}

	time.Sleep(3 * time.Second)
	samp, _ := sampleServer("charon")

	wg.Wait()
	close(resCh)

	var total float64
	var ok int
	for r := range resCh {
		if r.err != nil {
			t.Logf("iperf3 client failed: %v", r.err)
			continue
		}
		total += r.mbps
		ok++
	}
	per := 0.0
	if ok > 0 {
		per = total / float64(ok)
	}
	if ok == 0 {
		t.Errorf("all %d ikev2 connections failed", n)
	}
	return tierResult{
		aggregateMbps:    total,
		perClientMbps:    per,
		cpuPercent:       samp.cpuPercent,
		rssKB:            samp.rssKB,
		succeededClients: ok,
	}
}

// parseSwanctlLocalVIPs scans `swanctl --list-sas` text output for each
// connection's "local virtual IPs" line to learn its assigned tunnel
// source address -- swanctl has no machine-readable output mode short of
// the VICI protocol itself, so this greps the same human-readable report
// an operator would read.
// parseSwanctlLocalVIPs scans `swanctl --list-sas` text for each
// connection's assigned virtual IP. strongSwan 5.9's format gives it two
// ways -- inline next to the IKE_SA's local identity ("local 'CN=...' @
// host[port] [10.9.0.1]") and again as the child SA's own traffic
// selector ("local  10.9.0.1/32") -- neither of which is the
// "local virtual IPs:" summary line some other strongSwan versions print;
// this matches the child-SA selector form, confirmed live against 5.9.8.
func parseSwanctlLocalVIPs(out string, connNames []string) map[string]string {
	result := map[string]string{}
	var current string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, conn := range connNames {
			if strings.HasPrefix(trimmed, conn+":") {
				current = conn
			}
		}
		if current == "" || result[current] != "" {
			continue
		}
		if strings.HasPrefix(trimmed, "local ") && strings.HasSuffix(trimmed, "/32") {
			ip := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "local")), "/32")
			result[current] = strings.TrimSpace(ip)
		}
	}
	return result
}
