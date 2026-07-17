//go:build e2eload

package loadtest

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn/xray"
)

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

const xrayDomain = "loadtest.local"

func TestLoadXray(t *testing.T) {
	ctx := context.Background()
	sshClient := newSSHClient(t)
	store := newFakeXrayStore()
	p := xray.New(xray.Options{
		Instance: "loadtest:xray", ConfigPath: "/usr/local/etc/xray/config.json",
		ServiceName: "xray", PublicHost: serverIP,
		SSH: sshClient, Store: store, Enc: fakeSealer{},
	})

	// Self-signed cert at a protean-writable path -- avoids Reality's need
	// for a real, externally-reachable "dest" to steal a handshake from,
	// which would make this load test depend on live internet egress from
	// the sandbox. TLS + Vision is a real, supported Xray strategy on its
	// own, just not the anti-DPI-focused one. /etc/xray isn't among the
	// confDirs bootstrap chowns to protean (unlike /usr/local/etc/xray),
	// and the SSH session runs as protean, not root -- put it under the
	// dir that's actually writable.
	const certPath = "/usr/local/etc/xray/tls/cert.pem"
	const keyPath = "/usr/local/etc/xray/tls/key.pem"
	// -addext subjectAltName is required: Go's TLS stack (what Xray-core
	// itself uses) has rejected CN-only certs since Go 1.15 ("certificate
	// relies on legacy Common Name field, use SANs instead") -- confirmed
	// live, a CN-only cert here made every client TLS handshake fail.
	if _, err := sshClient.Run(ctx, "mkdir -p /usr/local/etc/xray/tls && "+
		"openssl req -x509 -newkey rsa:2048 -nodes -days 2 "+
		"-keyout "+keyPath+" -out "+certPath+" "+
		"-subj '/CN="+xrayDomain+"' -addext 'subjectAltName=DNS:"+xrayDomain+"'"); err != nil {
		t.Fatalf("generate self-signed cert: %v", err)
	}
	// Current Xray-core removed "allowInsecure" client-side (self-signed
	// certs would otherwise be rejected outright: "The feature
	// allowInsecure has been removed and migrated to
	// pinnedPeerCertSha256") -- confirmed live against 26.3.27. Pin the
	// cert's own fingerprint instead of disabling verification.
	fpOut, err := sshClient.Run(ctx, "openssl x509 -in "+certPath+" -outform DER | openssl dgst -sha256 -hex | awk '{print $2}'")
	if err != nil {
		t.Fatalf("compute cert fingerprint: %v", err)
	}
	certSHA256 := strings.TrimSpace(fpOut)

	if err := p.Apply(ctx, "vless-vision-tls", xray.Params{
		"port": "8443", "domain": xrayDomain, "cert_path": certPath, "key_path": keyPath,
	}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	assertActive(t, ctx, sshClient, "xray")

	// A plain HTTP payload to fetch through the tunnel -- xray's Vless
	// inbound is a TCP+TLS proxy, not a TUN device, so throughput here is
	// measured via curl-through-SOCKS instead of iperf3 (a genuinely
	// different, and correct, measurement method for what Xray actually
	// is -- see docs/SYSTEM-REQUIREMENTS.md).
	if _, err := sshClient.Run(ctx, "mkdir -p /tmp/payload && "+
		"dd if=/dev/urandom of=/tmp/payload/blob bs=1M count=64 2>/dev/null"); err != nil {
		t.Fatalf("prepare payload: %v", err)
	}
	// setsid + </dev/null: a plain trailing "&" isn't enough to detach from
	// a non-interactive SSH exec session -- the session hangs waiting for
	// the backgrounded process's inherited fds to close, confirmed live
	// ("context deadline exceeded" despite stdout/stderr redirection alone,
	// when chained onto the same command as the blocking mkdir/dd above).
	if _, err := sshClient.Run(ctx, "setsid python3 -m http.server 8080 --bind "+serverIP+
		" --directory /tmp/payload </dev/null >/tmp/http.log 2>&1 &"); err != nil {
		t.Fatalf("start payload server: %v", err)
	}
	time.Sleep(time.Second)

	for _, n := range concurrencyTiers() {
		n := n
		t.Run(fmt.Sprintf("concurrency=%d", n), func(t *testing.T) {
			r := loadXrayTier(t, ctx, sshClient, p, n, certSHA256)
			recordResult("xray", n, r)
		})
	}
}

func loadXrayTier(t *testing.T, ctx context.Context, sshClient *sshexec.Client, p *xray.Provider, n int, certSHA256 string) tierResult {
	t.Helper()
	var clientNames []string
	var nss []string
	t.Cleanup(func() {
		for _, ns := range nss {
			delPeerNS(ns)
		}
		for _, name := range clientNames {
			_ = p.RemoveClient(ctx, name)
		}
	})

	type target struct {
		ns  string
		uri string
	}
	var targets []target

	for i := 0; i < n; i++ {
		name := fmt.Sprintf("xray-p%d", i)
		if err := p.AddClient(ctx, name); err != nil {
			t.Fatalf("AddClient %d: %v", i, err)
		}
		clientNames = append(clientNames, name)

		links, err := p.ClientLinks(ctx)
		if err != nil {
			t.Fatalf("ClientLinks %d: %v", i, err)
		}
		var link string
		for _, l := range links {
			if l.Name == name {
				link = l.Link
				break
			}
		}
		if link == "" {
			t.Fatalf("no link found for client %d (%s)", i, name)
		}

		ns := fmt.Sprintf("xr%d", i)
		newPeerNS(t, ns, 120+i)
		nss = append(nss, ns)

		confJSON, err := buildXrayClientConfig(link, serverIP, certSHA256)
		if err != nil {
			t.Fatalf("buildXrayClientConfig %d: %v", i, err)
		}
		confPath := fmt.Sprintf("/tmp/%s.json", ns)
		clientWriteFile(t, confPath, confJSON)
		clientExecNSBg(t, ns, fmt.Sprintf("xray run -config %s", confPath))

		targets = append(targets, target{ns: ns})
	}

	// AddClient triggers a config re-apply + service restart each time;
	// give the server a moment to settle before measuring, longer at
	// higher concurrency since each AddClient call restarts it again.
	time.Sleep(time.Duration(3+n/10) * time.Second)

	resCh := make(chan iperfClientResult, n)
	var wg sync.WaitGroup
	for _, tg := range targets {
		tg := tg
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := clientExecNSErr(tg.ns, fmt.Sprintf(
				"curl -s -x socks5h://127.0.0.1:1080 http://%s:8080/blob -o /dev/null -w '%%{speed_download}'",
				serverIP))
			if err != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("ns=%s: %w", tg.ns, err)}
				return
			}
			bytesPerSec, perr := strconv.ParseFloat(strings.TrimSpace(out), 64)
			if perr != nil {
				resCh <- iperfClientResult{err: fmt.Errorf("ns=%s parse %q: %w", tg.ns, out, perr)}
				return
			}
			resCh <- iperfClientResult{mbps: bytesPerSec * 8 / 1_000_000}
		}()
	}

	time.Sleep(1 * time.Second)
	samp, _ := sampleServer("xray")

	wg.Wait()
	close(resCh)

	var total float64
	var ok int
	for r := range resCh {
		if r.err != nil {
			t.Logf("curl client failed: %v", r.err)
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
		t.Errorf("all %d xray clients failed", n)
	}
	return tierResult{
		aggregateMbps:    total,
		perClientMbps:    per,
		cpuPercent:       samp.cpuPercent,
		rssKB:            samp.rssKB,
		succeededClients: ok,
	}
}

// buildXrayClientConfig turns a vless:// share link (as produced by
// internal/vpn/xray's vless-vision-tls strategy) into a minimal
// xray-core client config: a loopback SOCKS inbound + a matching VLESS
// outbound. No code in the repo builds this today (server-side only
// generates inbounds); every field here is parsed straight out of the
// link's own scheme/userinfo/host/query, not guessed.
//
// connectAddr overrides the link's own host for the actual TCP
// destination: the link legitimately carries the operator's real DNS
// name (what a real client would resolve), which doesn't resolve inside
// this sandbox's netns -- the domain is still used for SNI, exactly as a
// real client would, only the connection target differs. certSHA256
// pins the self-signed test cert in place of "allowInsecure", which
// current Xray-core (26.x) rejects outright client-side.
func buildXrayClientConfig(link, connectAddr, certSHA256 string) (string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return "", fmt.Errorf("parse link: %w", err)
	}
	if u.Scheme != "vless" {
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	uuid := u.User.Username()
	port := u.Port()
	q := u.Query()

	return fmt.Sprintf(`{
  "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"udp": false}}],
  "outbounds": [{
    "protocol": "vless",
    "settings": {"vnext": [{"address": %q, "port": %s, "users": [{"id": %q, "encryption": "none", "flow": %q}]}]},
    "streamSettings": {
      "network": %q,
      "security": %q,
      "tlsSettings": {"serverName": %q, "pinnedPeerCertSha256": %q}
    }
  }]
}`, connectAddr, port, uuid, q.Get("flow"), q.Get("type"), q.Get("security"), q.Get("sni"), certSHA256), nil
}
