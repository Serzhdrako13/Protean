package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is a minimal in-process SSH server that executes each "exec"
// request through the local shell, so the real Client is exercised end-to-end
// (dial, handshake, session, ctx cancellation) without any external host.
type testServer struct {
	ln       net.Listener
	hostAuth string // server host key in authorized_keys line format
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		// Accept any public key; the client identity isn't what's under test.
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{ln: ln, hostAuth: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))}
	go ts.serve(cfg)
	t.Cleanup(func() { _ = ln.Close() })
	return ts
}

func (ts *testServer) serve(cfg *ssh.ServerConfig) {
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			return
		}
		go ts.handleConn(conn, cfg)
	}
}

func (ts *testServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go ts.handleSession(ch, chReqs)
	}
}

func (ts *testServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var m struct{ Command string }
		_ = ssh.Unmarshal(req.Payload, &m)
		_ = req.Reply(true, nil)

		cmd := exec.Command("sh", "-c", m.Command)
		cmd.Stdout = ch
		cmd.Stderr = ch.Stderr()
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				code = 1
			}
		}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		_ = ch.Close()
		return
	}
}

// newClient wires a Client to the test server, writing a throwaway client key
// to disk (New reads it from a path).
func newClient(t *testing.T, ts *testServer, cmdTimeout time.Duration) *Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ts.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	c, err := New(Config{
		Host: host, Port: port, User: "test", KeyPath: keyPath,
		HostKey: ts.hostAuth, CmdTimeout: cmdTimeout,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestRunOutput(t *testing.T) {
	c := newClient(t, newTestServer(t), 0)
	out, err := c.Run(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("got %q, want hello", out)
	}
}

func TestReadWriteFileRoundTrip(t *testing.T) {
	c := newClient(t, newTestServer(t), 0)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "conf")
	content := "[Interface]\nPrivateKey = k\n# with 'quotes' and $vars\n"
	if err := c.WriteFile(ctx, path, content); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := c.ReadFile(ctx, path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimRight(got, "\n") != strings.TrimRight(content, "\n") {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, content)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	c := newClient(t, newTestServer(t), 0)
	_, err := c.Run(context.Background(), "echo oops >&2; exit 3")
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(err.Error(), "oops") {
		t.Errorf("stderr not surfaced: %v", err)
	}
}

func TestRunContextCancel(t *testing.T) {
	c := newClient(t, newTestServer(t), 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()

	start := time.Now()
	_, err := c.Run(ctx, "sleep 5")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error on cancel")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Run did not return promptly on cancel: %v", elapsed)
	}
}

func TestRunCmdTimeout(t *testing.T) {
	c := newClient(t, newTestServer(t), 200*time.Millisecond)
	start := time.Now()
	_, err := c.Run(context.Background(), "sleep 5")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("command not bounded by CmdTimeout: %v", elapsed)
	}
}

func TestPingAndStats(t *testing.T) {
	c := newClient(t, newTestServer(t), 0)
	ctx := context.Background()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	_, _ = c.Run(ctx, "exit 1") // bump error counter
	st := c.Stats()
	if st.Commands < 2 {
		t.Errorf("commands = %d, want >= 2", st.Commands)
	}
	if st.Errors < 1 {
		t.Errorf("errors = %d, want >= 1", st.Errors)
	}
}

func TestHostKeyMismatchRejected(t *testing.T) {
	ts := newTestServer(t)
	c := newClient(t, ts, 0)
	// Re-pin a DIFFERENT host key: the connection must fail.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(other)
	cb, err := buildHostKeyCallback(Config{HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))})
	if err != nil {
		t.Fatal(err)
	}
	c.clientCfg.HostKeyCallback = cb
	if _, err := c.Run(context.Background(), "echo hi"); err == nil {
		t.Fatal("expected host-key mismatch to reject the connection")
	}
}
