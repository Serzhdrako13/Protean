//go:build e2eload

// Load test: drives real client tunnels (WireGuard/AmneziaWG, OpenVPN,
// IKEv2, Xray) against a real server provisioned exactly like
// test/e2elab's own lab, at increasing concurrency (1/10/50 simulated
// peers), measuring real throughput (iperf3 for the TUN/XFRM-based
// protocols, curl-through-SOCKS for Xray) and sampling the server's
// CPU%/RSS. See docs/SYSTEM-REQUIREMENTS.md for the resulting numbers and
// their honesty caveats (this sandbox's hardware, not a cloud vCPU).
//
// Separate, heavier build tag from test/e2elab's own `e2elab` -- this
// needs a second (client) container, real package installs in both, and
// takes noticeably longer. Manual-only even in CI (see ci.yml's
// `e2e-load` job).
package loadtest

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
)

const (
	serverImage     = "protean-loadtest:server"
	clientImage     = "protean-loadtest:client"
	serverContainer = "protean-loadtest-server"
	clientContainer = "protean-loadtest-client"
	networkName     = "protean-loadtest-net"
	bootstrapUser   = "ci-bootstrap"
	serviceUser     = "protean"
)

var (
	testKeyPEM []byte
	serverIP   string
)

func TestMain(m *testing.M) {
	if os.Getenv("PROTEAN_E2ELOAD") != "1" {
		fmt.Println("PROTEAN_E2ELOAD not set; skipping the load test (see test/e2elab/loadtest/README.md)")
		os.Exit(0)
	}
	os.Exit(runMain(m))
}

func thisDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// repoRoot: three levels up from test/e2elab/loadtest.
func repoRoot() string { return filepath.Dir(filepath.Dir(filepath.Dir(thisDir()))) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func runMain(m *testing.M) int {
	key, err := os.ReadFile(filepath.Join(repoRoot(), "test", "e2elab", "testkey"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read testkey:", err)
		return 1
	}
	testKeyPEM = key

	root := repoRoot()
	dockerfile := envOr("E2ELOAD_SERVER_DOCKERFILE", filepath.Join(root, "test/e2elab/dockerfiles/apt.Dockerfile"))
	baseImage := envOr("E2ELOAD_SERVER_BASE_IMAGE", "debian:12")

	fmt.Printf("building server image %s (BASE_IMAGE=%s)\n", dockerfile, baseImage)
	if out, err := runCmd("docker", "build", "-f", dockerfile, "--build-arg", "BASE_IMAGE="+baseImage, "-t", serverImage, root); err != nil {
		fmt.Fprintln(os.Stderr, "server image build failed:", out)
		return 1
	}

	fmt.Println("building client image")
	if out, err := runCmd("docker", "build", "-f", filepath.Join(thisDir(), "client.Dockerfile"), "-t", clientImage, root); err != nil {
		fmt.Fprintln(os.Stderr, "client image build failed:", out)
		return 1
	}

	_, _ = runCmd("docker", "rm", "-f", serverContainer)
	_, _ = runCmd("docker", "rm", "-f", clientContainer)
	_, _ = runCmd("docker", "network", "rm", networkName)

	if _, err := runCmd("docker", "network", "create", networkName); err != nil {
		fmt.Fprintln(os.Stderr, "network create failed")
		return 1
	}
	defer func() {
		if os.Getenv("E2ELOAD_KEEP_CONTAINERS") != "" {
			return
		}
		_ = exec.Command("docker", "rm", "-f", serverContainer).Run()
		_ = exec.Command("docker", "rm", "-f", clientContainer).Run()
		_ = exec.Command("docker", "network", "rm", networkName).Run()
	}()

	if out, err := runCmd("docker", "run", "-d", "--name", serverContainer,
		"--privileged", "--cgroupns=host", "--network", networkName,
		"--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/run/lock",
		"-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		serverImage); err != nil {
		fmt.Fprintln(os.Stderr, "server run failed:", out)
		return 1
	}

	if out, err := runCmd("docker", "run", "-d", "--name", clientContainer,
		"--privileged", "--network", networkName, clientImage); err != nil {
		fmt.Fprintln(os.Stderr, "client run failed:", out)
		return 1
	}

	ip, err := containerIP(serverContainer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "get server ip:", err)
		return 1
	}
	serverIP = ip
	fmt.Println("server container ip:", serverIP)

	if err := waitForSSH(serverIP, 30*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "sshd never came up:", err)
		out, _ := exec.Command("docker", "logs", serverContainer).CombinedOutput()
		fmt.Fprintln(os.Stderr, string(out))
		return 1
	}

	if err := bootstrap(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap failed:", err)
		return 1
	}

	// iperf3 + a plain HTTP payload server aren't part of the distro-matrix
	// image (that image stays minimal/distro-neutral on purpose) -- install
	// them live, only for this load test.
	if out, err := runCmd("docker", "exec", serverContainer, "bash", "-c",
		"apt-get update -qq && apt-get install -y -qq iperf3 python3 >/dev/null"); err != nil {
		fmt.Fprintln(os.Stderr, "install iperf3/python3 on server:", out)
		return 1
	}

	code := m.Run()
	printResults()
	writeResultsJSON()
	return code
}

// --- concurrency tiers + result recording ---

// concurrencyTiers defaults to 1/10/50 simulated peers per protocol, per
// docs/SYSTEM-REQUIREMENTS.md's methodology. Override via E2ELOAD_TIERS
// (comma-separated) to scale down on constrained hardware -- documented
// there as an explicit, visible choice, not a silent cap.
func concurrencyTiers() []int {
	v := os.Getenv("E2ELOAD_TIERS")
	if v == "" {
		return []int{1, 10, 50}
	}
	var out []int
	for _, s := range strings.Split(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{1, 10, 50}
	}
	return out
}

type tierResult struct {
	concurrency      int
	aggregateMbps    float64
	perClientMbps    float64
	cpuPercent       float64
	rssKB            int
	succeededClients int
}

type namedResult struct {
	protocol string
	tierResult
}

var (
	resultsMu sync.Mutex
	results   []namedResult
)

func recordResult(protocol string, n int, r tierResult) {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	r.concurrency = n
	results = append(results, namedResult{protocol: protocol, tierResult: r})
}

func printResults() {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	if len(results) == 0 {
		return
	}
	fmt.Println("\n=== Load test results ===")
	fmt.Printf("%-12s %5s %8s %12s %12s %8s %8s\n",
		"protocol", "N", "ok", "aggMbps", "perClient", "cpu%", "rssMB")
	for _, r := range results {
		fmt.Printf("%-12s %5d %8d %12.2f %12.2f %8.1f %8.1f\n",
			r.protocol, r.concurrency, r.succeededClients, r.aggregateMbps, r.perClientMbps,
			r.cpuPercent, float64(r.rssKB)/1024)
	}
}

// writeResultsJSON drops the raw numbers next to the test binary so
// docs/SYSTEM-REQUIREMENTS.md's methodology can cite exact figures rather
// than transcribed-by-hand ones. Best-effort -- a write failure here
// shouldn't fail the whole run.
func writeResultsJSON() {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	path := envOr("E2ELOAD_RESULTS_JSON", filepath.Join(thisDir(), "results.json"))
	var b strings.Builder
	b.WriteString("[\n")
	for i, r := range results {
		if i > 0 {
			b.WriteString(",\n")
		}
		fmt.Fprintf(&b, `  {"protocol": %q, "concurrency": %d, "succeeded": %d, "aggregate_mbps": %.2f, "per_client_mbps": %.2f, "cpu_percent": %.1f, "rss_kb": %d}`,
			r.protocol, r.concurrency, r.succeededClients, r.aggregateMbps, r.perClientMbps, r.cpuPercent, r.rssKB)
	}
	b.WriteString("\n]\n")
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

// iperfClientResult is what runIperfTier collects from one netns's iperf3
// client run.
type iperfClientResult struct {
	mbps float64
	err  error
}

// runIperfTier runs one real iperf3 client per netns in nss, all
// concurrently, against iperf3 servers already listening on the server
// container at basePort..basePort+len(nss)-1 bound to serverTunnelIP, then
// samples the server's CPU% (and, if procName is non-empty, that process's
// RSS) once traffic has been flowing for a couple of seconds.
func runIperfTier(t *testing.T, nss []string, serverTunnelIP string, basePort int, procName string) tierResult {
	t.Helper()
	n := len(nss)
	resCh := make(chan iperfClientResult, n)
	var wg sync.WaitGroup
	for i, ns := range nss {
		i, ns := i, ns
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := basePort + i
			out, err := clientExecNSErr(ns, fmt.Sprintf("iperf3 -c %s -p %d -t 6 -J", serverTunnelIP, port))
			if err != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("ns=%s: %w", ns, err)}
				return
			}
			mbps, perr := parseIperfSentMbps(out)
			if perr != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("ns=%s parse: %w", ns, perr)}
				return
			}
			resCh <- iperfClientResult{mbps: mbps}
		}()
	}

	// Sample resource usage roughly mid-run: iperf3 -t 6 gives a ~6s
	// window, sample after 3s.
	go func() {
		time.Sleep(3 * time.Second)
	}()
	time.Sleep(3 * time.Second)
	samp, _ := sampleServer(procName)

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
		t.Errorf("all %d iperf3 clients failed", n)
	}
	return tierResult{
		aggregateMbps:    total,
		perClientMbps:    per,
		cpuPercent:       samp.cpuPercent,
		rssKB:            samp.rssKB,
		succeededClients: ok,
	}
}

// parseIperfSentMbps extracts end.sum_sent.bits_per_second from iperf3's
// -J JSON output without pulling in a JSON dependency for one field --
// deliberately simple regex-free scan since the field is a plain number in
// a predictable position.
func parseIperfSentMbps(jsonOut string) (float64, error) {
	const key = `"bits_per_second":`
	idx := strings.LastIndex(jsonOut, `"sum_sent"`)
	if idx < 0 {
		return 0, fmt.Errorf("no sum_sent in output: %s", jsonOut)
	}
	rest := jsonOut[idx:]
	kidx := strings.Index(rest, key)
	if kidx < 0 {
		return 0, fmt.Errorf("no bits_per_second after sum_sent")
	}
	rest = strings.TrimSpace(rest[kidx+len(key):])
	end := strings.IndexAny(rest, ",}\n")
	if end < 0 {
		end = len(rest)
	}
	bps, err := strconv.ParseFloat(strings.TrimSpace(rest[:end]), 64)
	if err != nil {
		return 0, err
	}
	return bps / 1_000_000, nil
}

func containerIP(name string) (string, error) {
	out, err := runCmd("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(out)
	if ip == "" {
		return "", fmt.Errorf("empty IP for container %s", name)
	}
	return ip, nil
}

func waitForSSH(host string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(host, "22")
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

// bootstrap mirrors test/e2elab/lab_test.go's own bootstrap() -- the real
// sshexec.BootstrapHost path -- against the load-test's server container.
func bootstrap() error {
	bootstrapOnce.Do(func() {
		pubBytes, err := os.ReadFile(filepath.Join(repoRoot(), "test", "e2elab", "testkey.pub"))
		if err != nil {
			bootstrapErr = err
			return
		}
		cfg := sshexec.Config{Host: serverIP, Port: 22, User: bootstrapUser, Timeout: 10 * time.Second}
		auth := sshexec.BootstrapAuth{KeyPEM: testKeyPEM}
		_, bootstrapErr = sshexec.BootstrapHost(context.Background(), cfg, auth, serviceUser,
			strings.TrimSpace(string(pubBytes)), hostboot.InstallerScript(), hostboot.InstallerPath)
	})
	return bootstrapErr
}

func newSSHClient(t *testing.T) *sshexec.Client {
	t.Helper()
	c, err := sshexec.New(sshexec.Config{
		Host: serverIP, Port: 22, User: serviceUser, KeyPEM: testKeyPEM,
		Timeout: 10 * time.Second, CmdTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("sshexec.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func assertActive(t *testing.T, ctx context.Context, client *sshexec.Client, unit string) {
	t.Helper()
	var out string
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		out, err = client.Run(ctx, "systemctl is-active "+unit)
		if err == nil && strings.TrimSpace(out) == "active" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("unit %q not active after retries: out=%q err=%v", unit, out, err)
}

// --- client-container exec helpers ---

// clientExec runs cmd via `sh -c` in the client container's ROOT network
// namespace (no netns targeting).
func clientExec(t *testing.T, cmd string) string {
	t.Helper()
	out, err := runCmd("docker", "exec", clientContainer, "sh", "-c", cmd)
	if err != nil {
		t.Fatalf("client exec %q: %v", cmd, err)
	}
	return out
}

func clientExecErr(cmd string) (string, error) {
	return runCmd("docker", "exec", clientContainer, "sh", "-c", cmd)
}

// clientExecNS runs cmd inside network namespace ns in the client
// container.
func clientExecNS(t *testing.T, ns, cmd string) string {
	t.Helper()
	full := fmt.Sprintf("ip netns exec %s sh -c %s", ns, shellSingleQuote(cmd))
	out, err := runCmd("docker", "exec", clientContainer, "sh", "-c", full)
	if err != nil {
		t.Fatalf("client exec [ns %s] %q: %v", ns, cmd, err)
	}
	return out
}

func clientExecNSErr(ns, cmd string) (string, error) {
	full := fmt.Sprintf("ip netns exec %s sh -c %s", ns, shellSingleQuote(cmd))
	return runCmd("docker", "exec", clientContainer, "sh", "-c", full)
}

// clientExecNSBg starts cmd inside netns ns in the client container,
// detached (backgrounded via nohup+&), for long-running daemons
// (openvpn/charon/xray client processes).
func clientExecNSBg(t *testing.T, ns, cmd string) {
	t.Helper()
	full := fmt.Sprintf("ip netns exec %s sh -c %s >/tmp/%s.log 2>&1 &", ns, shellSingleQuote(cmd), ns)
	if _, err := runCmd("docker", "exec", "-d", clientContainer, "sh", "-c", full); err != nil {
		t.Fatalf("client bg exec [ns %s] %q: %v", ns, cmd, err)
	}
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// clientWriteFile writes content to path inside the client container (its
// filesystem is shared across all its network namespaces -- only the
// network stack differs per netns, so no per-ns targeting is needed here).
func clientWriteFile(t *testing.T, path, content string) {
	t.Helper()
	cmd := exec.Command("docker", "exec", "-i", clientContainer, "sh", "-c", "cat > "+path)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clientWriteFile %s: %v: %s", path, err, out)
	}
}

// --- per-simulated-peer network namespace plumbing ---
//
// Each simulated peer gets its own netns inside the client container, with
// a veth pair back to the container's root netns and a NAT rule so it can
// reach the server container's real IP -- a real, independent "machine"
// from the tunnel software's point of view, exactly mirroring the
// wgfamily integration test's netns-per-instance approach
// (internal/vpn/wgfamily/integration_test.go), just for the client role
// instead of the server role.

var natOnce sync.Once

func ensureNAT(t *testing.T) {
	t.Helper()
	natOnce.Do(func() {
		clientExec(t, "echo 1 > /proc/sys/net/ipv4/ip_forward")
		clientExec(t, "iptables -t nat -C POSTROUTING -s 10.90.0.0/16 -j MASQUERADE 2>/dev/null || "+
			"iptables -t nat -A POSTROUTING -s 10.90.0.0/16 -j MASQUERADE")
	})
}

// newPeerNS creates network namespace ns (idx in [0,255)) with veth
// connectivity to the client container's root netns and a route to the
// server. Returns the peer-side address (no mask) for convenience.
func newPeerNS(t *testing.T, ns string, idx int) string {
	t.Helper()
	ensureNAT(t)
	rootAddr := fmt.Sprintf("10.90.%d.1", idx)
	peerAddr := fmt.Sprintf("10.90.%d.2", idx)
	vethRoot := "vr" + ns
	vethPeer := "vp" + ns

	_, _ = clientExecErr(fmt.Sprintf("ip netns del %s 2>/dev/null", ns))
	clientExec(t, fmt.Sprintf("ip netns add %s", ns))
	clientExec(t, fmt.Sprintf("ip link add %s type veth peer name %s", vethRoot, vethPeer))
	clientExec(t, fmt.Sprintf("ip link set %s netns %s", vethPeer, ns))
	clientExec(t, fmt.Sprintf("ip addr add %s/30 dev %s", rootAddr, vethRoot))
	clientExec(t, fmt.Sprintf("ip link set %s up", vethRoot))
	clientExecNS(t, ns, fmt.Sprintf("ip addr add %s/30 dev %s", peerAddr, vethPeer))
	clientExecNS(t, ns, fmt.Sprintf("ip link set %s up", vethPeer))
	clientExecNS(t, ns, "ip link set lo up")
	clientExecNS(t, ns, fmt.Sprintf("ip route add default via %s", rootAddr))
	return peerAddr
}

func delPeerNS(ns string) {
	_, _ = clientExecErr(fmt.Sprintf("ip netns del %s 2>/dev/null", ns))
	_, _ = clientExecErr(fmt.Sprintf("ip link del vr%s 2>/dev/null", ns))
}

// --- resource sampling ---

type sample struct {
	cpuPercent float64
	rssKB      int
}

// sampleServer takes a one-shot `docker stats` reading (CPU% across the
// whole container, averaged over its short internal sampling window) plus
// the given process's RSS from /proc, both AFTER load has been running for
// a few seconds so the number reflects steady state, not startup.
func sampleServer(proc string) (sample, error) {
	out, err := runCmd("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", serverContainer)
	if err != nil {
		return sample{}, err
	}
	cpuStr := strings.TrimSuffix(strings.TrimSpace(out), "%")
	cpu, _ := strconv.ParseFloat(cpuStr, 64)

	pidOut, err := runCmd("docker", "exec", serverContainer, "sh", "-c", "pgrep -x "+proc+" | head -1")
	rss := 0
	if err == nil {
		pid := strings.TrimSpace(pidOut)
		if pid != "" {
			statusOut, err := runCmd("docker", "exec", serverContainer, "sh", "-c", "grep VmRSS /proc/"+pid+"/status")
			if err == nil {
				fields := strings.Fields(statusOut)
				if len(fields) >= 2 {
					rss, _ = strconv.Atoi(fields[1])
				}
			}
		}
	}
	return sample{cpuPercent: cpu, rssKB: rss}, nil
}

// --- shared vpn.PeerSpec helper ---

func peerSpec(name string, allowedIPs ...string) vpn.PeerSpec {
	return vpn.PeerSpec{Name: name, AllowedIPs: allowedIPs}
}

// --- shared fakes: DB layer already has its own dbtest coverage; this
// harness proves the HOST side for real, same fast-fake pattern as
// test/e2elab/lab_test.go. ---

type fakeSealer struct{}

func (fakeSealer) Seal(s string) ([]byte, error) { return []byte(s), nil }
func (fakeSealer) Open(b []byte) (string, error) { return string(b), nil }
