//go:build e2elab

package e2elab

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"protean/internal/hostboot"
	"protean/internal/sshexec"
	"protean/internal/vpn"
	"protean/internal/vpn/ikev2"
	"protean/internal/vpn/openvpn"
	"protean/internal/vpn/pki"
	"protean/internal/vpn/xray"
)

const (
	imageName     = "protean-e2elab:test"
	containerName = "protean-e2elab"
	sshHost       = "127.0.0.1"
	sshPort       = 2222
	bootstrapUser = "ci-bootstrap"
	serviceUser   = "protean"

	// Defaults match this lab's original single-distro setup -- override
	// via E2ELAB_DOCKERFILE/E2ELAB_BASE_IMAGE to target any other family/
	// version in test/e2elab/dockerfiles/ (see README.md's distro table).
	defaultDockerfile = "test/e2elab/dockerfiles/apt.Dockerfile"
	defaultBaseImage  = "debian:12"
)

var testKeyPEM []byte

func TestMain(m *testing.M) {
	if os.Getenv("PROTEAN_E2ELAB") != "1" {
		fmt.Println("PROTEAN_E2ELAB not set; skipping the e2e lab (see test/e2elab/README.md)")
		os.Exit(0)
	}
	os.Exit(runMain(m))
}

func thisDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// repoRoot is the docker build CONTEXT: the Dockerfile templates COPY both
// scripts/protean-installer.sh (repo root) and test/e2elab/testkey.pub, so
// the build context has to be the repo root, not this directory -- unlike
// the original single-Dockerfile setup, which lived entirely inside
// test/e2elab and needed no path outside it.
func repoRoot() string { return filepath.Dir(filepath.Dir(thisDir())) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runMain(m *testing.M) int {
	key, err := os.ReadFile(filepath.Join(thisDir(), "testkey"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read testkey:", err)
		return 1
	}
	testKeyPEM = key

	root := repoRoot()
	dockerfile := envOr("E2ELAB_DOCKERFILE", defaultDockerfile)
	if !filepath.IsAbs(dockerfile) {
		dockerfile = filepath.Join(root, dockerfile)
	}
	baseImage := envOr("E2ELAB_BASE_IMAGE", defaultBaseImage)
	buildArgs := []string{
		"build", "-f", dockerfile, "--build-arg", "BASE_IMAGE=" + baseImage,
		"-t", imageName, root,
	}
	fmt.Printf("building %s (BASE_IMAGE=%s) from %s\n", dockerfile, baseImage, root)
	if out, err := exec.Command("docker", buildArgs...).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "docker build failed: %v\n%s\n", err, out)
		return 1
	}
	// Best-effort cleanup from a previous aborted run.
	_ = exec.Command("docker", "rm", "-f", containerName).Run()

	runArgs := []string{
		// --cgroupns=host: required on cgroup v2 hosts -- the default
		// cgroupns=private leaves systemd unable to get PID 1 delegation
		// at all (confirmed live: without it the container exits
		// immediately with no output whatsoever).
		"run", "-d", "--name", containerName, "--privileged", "--cgroupns=host",
		"--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"-p", fmt.Sprintf("%d:22", sshPort),
		imageName,
	}
	if out, err := exec.Command("docker", runArgs...).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "docker run failed: %v\n%s\n", err, out)
		return 1
	}
	defer func() {
		if os.Getenv("E2ELAB_KEEP_CONTAINER") != "" {
			return
		}
		_ = exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	if err := waitForSSH(30 * time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "sshd never came up:", err)
		out, _ := exec.Command("docker", "logs", containerName).CombinedOutput()
		fmt.Fprintln(os.Stderr, string(out))
		return 1
	}

	if err := bootstrap(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap failed:", err)
		return 1
	}

	return m.Run()
}

// waitForSSH waits until the server actually speaks SSH, not just until the
// TCP port accepts a connection -- confirmed live that a bare TCP dial
// succeeds well before sshd is ready to handshake (the port opens before
// the daemon finishes initializing), which otherwise surfaces as a
// "connection reset by peer" handshake failure moments later.
func waitForSSH(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(sshHost, strconv.Itoa(sshPort))
	var lastErr error
	for time.Now().Before(deadline) {
		if err := probeSSHBanner(addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timed out waiting for %s to speak SSH: %w", addr, lastErr)
}

func probeSSHBanner(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read banner: %w", err)
	}
	if string(buf[:n]) != "SSH-" {
		return fmt.Errorf("not an SSH banner: %q", buf[:n])
	}
	return nil
}

var (
	bootstrapOnce sync.Once
	bootstrapErr  error
)

// bootstrap drives the REAL sshexec.BootstrapHost -- the exact code path a
// real "Add server" runs -- against the lab container, standing up the
// "protean" service account from the ci-bootstrap identity baked into the
// image. Both identities share testKeyPEM for simplicity (a real deployment
// uses a distinct generated key per service account; this lab only needs
// one throwaway keypair for a throwaway container).
func bootstrap() error {
	bootstrapOnce.Do(func() {
		pubBytes, err := os.ReadFile(filepath.Join(thisDir(), "testkey.pub"))
		if err != nil {
			bootstrapErr = err
			return
		}
		cfg := sshexec.Config{Host: sshHost, Port: sshPort, User: bootstrapUser, Timeout: 10 * time.Second}
		auth := sshexec.BootstrapAuth{KeyPEM: testKeyPEM}
		_, bootstrapErr = sshexec.BootstrapHost(context.Background(), cfg, auth, serviceUser,
			strings.TrimSpace(string(pubBytes)), hostboot.InstallerScript(), hostboot.InstallerPath)
	})
	return bootstrapErr
}

func newSSHClient(t *testing.T) *sshexec.Client {
	t.Helper()
	c, err := sshexec.New(sshexec.Config{
		Host: sshHost, Port: sshPort, User: serviceUser, KeyPEM: testKeyPEM,
		Timeout: 10 * time.Second, CmdTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("sshexec.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// assertActive retries briefly before failing -- a fresh systemd boot can
// still be settling other units when the very first test in the suite
// runs (observed live: a one-off "inactive" immediately after a real
// `systemctl restart` had already returned success, gone on the next
// attempt a moment later). Real automation shouldn't assume instant
// convergence either, so this is a legitimate robustness fix, not masking
// a product bug -- rebuild()/EnsureServer already issue the
// enable+restart for real; this only tolerates the read-back racing it.
//
// Uses `systemctl show -p ActiveState --value`, not `is-active`: confirmed
// live that `is-active` on an aliased unit name (ipsec -> strongswan,
// openvpn -> openvpn-server@server, any Alias= target) can misreport
// "inactive" (exit 3) on systemd 232 (Astra Linux CE 2.12's bundled
// version) persistently after any `daemon-reload` -- not a timing race
// this retry loop would ever clear, since `show`'s own ActiveState always
// resolves correctly on the exact same unit at the exact same moment.
// `show` also always exits 0 (even for an unknown unit), sidestepping
// sshexec.Client.Run's stdout-discard-on-nonzero-exit behavior entirely.
func assertActive(t *testing.T, ctx context.Context, client *sshexec.Client, unit string) {
	t.Helper()
	var out string
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		out, err = client.Run(ctx, "systemctl show "+unit+" -p ActiveState --value")
		if err == nil && strings.TrimSpace(out) == "active" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Errorf("unit %q not active after retries: out=%q err=%v", unit, out, err)
}

// assertRevokedInHostCRL reads the CRL back from the REAL host and parses
// it with pki.ParseCRL (this session's own code) to confirm peerCertPEM's
// serial is really in RevokedCertificateEntries -- a genuine cryptographic
// check against what strongSwan/OpenVPN would themselves consult, not just
// "did some file get written."
func assertRevokedInHostCRL(t *testing.T, ctx context.Context, client *sshexec.Client, peerCertPEM, crlPath string) {
	t.Helper()
	crlPEM, err := client.ReadFile(ctx, crlPath)
	if err != nil {
		t.Fatalf("read CRL from host %s: %v", crlPath, err)
	}
	revoked, _, err := pki.ParseCRL(crlPEM)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	serial, err := pki.SerialFromCertPEM(peerCertPEM)
	if err != nil {
		t.Fatalf("parse peer cert serial: %v", err)
	}
	for _, r := range revoked {
		if r.Serial.Cmp(serial) == 0 {
			return
		}
	}
	t.Errorf("peer serial %s not found among %d entries in host CRL %s", serial, len(revoked), crlPath)
}

// --- fakes: DB layer is already covered by dbtest; this lab proves the
// HOST side for real, so an in-memory Store/Sealer is deliberately used
// here instead of a real Postgres -- same fast-fake pattern as this
// session's own revoke_csr_test.go/importpeer_test.go/provider_test.go. ---

type fakeSealer struct{}

func (fakeSealer) Seal(s string) ([]byte, error) { return []byte(s), nil }
func (fakeSealer) Open(b []byte) (string, error) { return string(b), nil }

type ovpnClient struct {
	cert, addr, subnets string
	encKey              []byte
}

type fakeOpenVPNStore struct {
	mu      sync.Mutex
	caCert  string
	caKey   []byte
	clients map[string]ovpnClient
	revoked []openvpn.RevokedCert
	crlNum  int64
}

func newFakeOpenVPNStore() *fakeOpenVPNStore {
	return &fakeOpenVPNStore{clients: map[string]ovpnClient{}}
}

func (s *fakeOpenVPNStore) clientCert(cn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[cn].cert
}

func (s *fakeOpenVPNStore) GetCAMaterial(context.Context, string) (string, []byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.caCert == "" {
		return "", nil, "", fmt.Errorf("none")
	}
	return s.caCert, s.caKey, "internal", nil
}
func (s *fakeOpenVPNStore) SaveCAMaterial(_ context.Context, _, cert string, key []byte, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caCert, s.caKey = cert, key
	return nil
}
func (s *fakeOpenVPNStore) SaveOpenVPNClient(_ context.Context, _, cn, cert string, key []byte, addr, subnets string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[cn] = ovpnClient{cert: cert, encKey: key, addr: addr, subnets: subnets}
	return nil
}
func (s *fakeOpenVPNStore) GetOpenVPNClient(_ context.Context, _, cn string) (string, []byte, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[cn]
	if !ok {
		return "", nil, "", "", fmt.Errorf("not found")
	}
	return c.cert, c.encKey, c.addr, c.subnets, nil
}
func (s *fakeOpenVPNStore) ListOpenVPNClients(context.Context, string) ([]string, []string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cns, addrs, subs []string
	for cn, c := range s.clients {
		cns = append(cns, cn)
		addrs = append(addrs, c.addr)
		subs = append(subs, c.subnets)
	}
	return cns, addrs, subs, nil
}
func (s *fakeOpenVPNStore) DeleteOpenVPNClient(_ context.Context, _, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, cn)
	return nil
}
func (s *fakeOpenVPNStore) AddRevokedCert(_ context.Context, _, serial, cn string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = append(s.revoked, openvpn.RevokedCert{Serial: serial, RevokedAt: time.Now()})
	return nil
}
func (s *fakeOpenVPNStore) ListRevokedCerts(context.Context, string) ([]openvpn.RevokedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked, nil
}
func (s *fakeOpenVPNStore) NextCRLNumber(context.Context, string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlNum++
	return s.crlNum, nil
}

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

func (s *fakeIKEv2Store) clientCert(cn string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clients[cn].cert
}

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

type fakeXrayStore struct {
	mu       sync.Mutex
	strategy string
	params   []byte
	relay    []byte
	clients  map[string]xray.ClientRow
}

func newFakeXrayStore() *fakeXrayStore { return &fakeXrayStore{clients: map[string]xray.ClientRow{}} }

func (s *fakeXrayStore) SaveInstance(_ context.Context, _, strategy string, encParams, encRelay []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strategy, s.params, s.relay = strategy, encParams, encRelay
	return nil
}
func (s *fakeXrayStore) GetInstance(context.Context, string) (string, []byte, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.strategy == "" {
		return "", nil, nil, fmt.Errorf("not configured")
	}
	return s.strategy, s.params, s.relay, nil
}
func (s *fakeXrayStore) SaveXrayClient(_ context.Context, _, name string, encCred []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[name] = xray.ClientRow{Name: name, EncCred: encCred}
	return nil
}
func (s *fakeXrayStore) ListXrayClients(context.Context, string) ([]xray.ClientRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]xray.ClientRow, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}
func (s *fakeXrayStore) DeleteXrayClient(_ context.Context, _, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, name)
	return nil
}

// --- the actual lifecycle tests ---

func TestE2ELabOpenVPN(t *testing.T) {
	ctx := context.Background()
	client := newSSHClient(t)
	store := newFakeOpenVPNStore()
	p := openvpn.New(openvpn.Options{
		Instance: "e2elab:openvpn", Interface: "server",
		ConfPath: "/etc/openvpn/server/server.conf", ServerDir: "/etc/openvpn/server",
		CCDDir: "/etc/openvpn/server/ccd-server", StatusPath: "/run/openvpn-server/status-server.log",
		ServiceName: "openvpn-server@server", PublicHost: sshHost,
		ListenPort: 1194, Proto: "udp", ServerNet: "10.8.0.0", ServerMask: "255.255.255.0",
		SSH: client, Store: store, Enc: fakeSealer{},
	})

	if err := p.EnsureServer(ctx, nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	assertActive(t, ctx, client, "openvpn-server@server")

	if _, err := p.AddPeer(ctx, vpn.PeerSpec{Name: "alice", AllowedIPs: []string{"10.8.0.10/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	certPEM := store.clientCert("alice")
	if certPEM == "" {
		t.Fatal("expected alice's cert to be stored")
	}

	if err := p.RemovePeer(ctx, "alice"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	// OpenVPN re-reads crl-verify per connection -- no restart needed or
	// expected for a revocation to take effect; confirm none happened.
	assertActive(t, ctx, client, "openvpn-server@server")
	assertRevokedInHostCRL(t, ctx, client, certPEM, "/etc/openvpn/server/crl.pem")
}

func TestE2ELabIKEv2(t *testing.T) {
	ctx := context.Background()
	client := newSSHClient(t)
	store := newFakeIKEv2Store()
	p := ikev2.New(ikev2.Options{
		Instance: "e2elab:ikev2", ConnName: "e2elab",
		SwanctlDir: "/etc/swanctl", ServiceName: "ipsec", ServerID: sshHost,
		Pool: "10.9.0.0/24", DNS: []string{"1.1.1.1"},
		SSH: client, Store: store, Enc: fakeSealer{},
	})

	if err := p.EnsureServer(ctx, nil, false); err != nil {
		t.Fatalf("EnsureServer: %v", err)
	}
	assertActive(t, ctx, client, "ipsec")

	if _, err := p.AddPeer(ctx, vpn.PeerSpec{Name: "bob", AllowedIPs: []string{"10.9.0.10/32"}}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	certPEM := store.clientCert("bob")
	if certPEM == "" {
		t.Fatal("expected bob's cert to be stored")
	}

	if err := p.RemovePeer(ctx, "bob"); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	assertActive(t, ctx, client, "ipsec")
	assertRevokedInHostCRL(t, ctx, client, certPEM, "/etc/swanctl/x509crl/crl.pem")
}

func TestE2ELabXray(t *testing.T) {
	ctx := context.Background()
	client := newSSHClient(t)
	store := newFakeXrayStore()
	p := xray.New(xray.Options{
		Instance: "e2elab:xray", ConfigPath: "/usr/local/etc/xray/config.json",
		ServiceName: "xray", PublicHost: sshHost,
		SSH: client, Store: store, Enc: fakeSealer{},
	})

	if err := p.Apply(ctx, "reality-vless-tcp", xray.Params{
		"sni": "www.microsoft.com", "dest": "www.microsoft.com:443", "port": "8443",
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertActive(t, ctx, client, "xray")

	links, err := p.ClientLinks(ctx)
	if err != nil || len(links) != 1 {
		t.Fatalf("ClientLinks: %+v err=%v", links, err)
	}
	if !strings.HasPrefix(links[0].Link, "vless://") {
		t.Errorf("unexpected link %q", links[0].Link)
	}

	confJSON, err := client.ReadFile(ctx, "/usr/local/etc/xray/config.json")
	if err != nil {
		t.Fatalf("read xray config from host: %v", err)
	}
	if !strings.Contains(confJSON, "reality") {
		t.Errorf("host xray config missing reality settings:\n%s", confJSON)
	}

	// Add a second client first -- an inbound always needs at least one
	// client (same invariant OpenVPN/IKEv2 enforce), so removing "default"
	// down to zero would correctly fail; this is about proving a *removed*
	// client's credential actually disappears from the live host config.
	if err := p.AddClient(ctx, "second"); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	if err := p.RemoveClient(ctx, "default"); err != nil {
		t.Fatalf("RemoveClient: %v", err)
	}
	assertActive(t, ctx, client, "xray")
	confJSON, err = client.ReadFile(ctx, "/usr/local/etc/xray/config.json")
	if err != nil {
		t.Fatalf("read xray config from host (after remove): %v", err)
	}
	if strings.Contains(confJSON, links[0].Link[len("vless://"):strings.Index(links[0].Link, "@")]) {
		t.Errorf("removed client's uuid still present in host config:\n%s", confJSON)
	}
}

func TestE2ELabIPForward(t *testing.T) {
	ctx := context.Background()
	client := newSSHClient(t)
	inst := vpn.NewInstaller(client)
	if err := inst.EnsureIPForward(ctx); err != nil {
		t.Fatalf("EnsureIPForward: %v", err)
	}
	// Read /proc directly rather than the "sysctl" binary -- a plain
	// (non-sudo) SSH exec session's PATH doesn't include /usr/sbin, where
	// sysctl actually lives, and this needs no privilege to read anyway.
	out, err := client.Run(ctx, "cat /proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatalf("read ip_forward: %v", err)
	}
	if strings.TrimSpace(out) != "1" {
		t.Errorf("ip_forward = %q, want 1", out)
	}
}

// TestE2ELabSSHFailureHandling runs last -- the container is expendable
// afterward. Confirms the panel degrades gracefully (a clean error, not a
// hang or a panic) when a managed host vanishes mid-operation.
func TestE2ELabSSHFailureHandling(t *testing.T) {
	ctx := context.Background()
	client := newSSHClient(t)

	if out, err := exec.Command("docker", "stop", containerName).CombinedOutput(); err != nil {
		t.Fatalf("docker stop: %v\n%s", err, out)
	}

	store := newFakeOpenVPNStore()
	p := openvpn.New(openvpn.Options{
		Instance: "e2elab:openvpn-down", Interface: "server",
		ConfPath: "/etc/openvpn/server/server.conf", ServerDir: "/etc/openvpn/server",
		CCDDir: "/etc/openvpn/server/ccd-server", ServiceName: "openvpn-server@server",
		ServerNet: "10.8.0.0", ServerMask: "255.255.255.0",
		SSH: client, Store: store, Enc: fakeSealer{},
	})

	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.EnsureServer(callCtx, nil, false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected an error provisioning against a stopped host, got nil")
		}
	case <-callCtx.Done():
		t.Error("EnsureServer hung past the context deadline instead of returning a clean error")
	}
}
