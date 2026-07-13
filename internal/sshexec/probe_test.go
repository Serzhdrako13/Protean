package sshexec

import (
	"context"
	"net"
	"strconv"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestProbeHostKey(t *testing.T) {
	ts := newTestServer(t)
	host, portStr, _ := net.SplitHostPort(ts.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	authorizedKey, fingerprint, err := ProbeHostKey(context.Background(), host, port, 0)
	if err != nil {
		t.Fatalf("ProbeHostKey: %v", err)
	}
	if authorizedKey != ts.hostAuth {
		t.Errorf("authorizedKey = %q, want %q", authorizedKey, ts.hostAuth)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ts.hostAuth))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if want := ssh.FingerprintSHA256(pub); fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", fingerprint, want)
	}
}

func TestProbeHostKeyConnectionRefused(t *testing.T) {
	// Bind and immediately close, to get a real port nothing is listening
	// on, so the dial itself fails distinctly from a handshake failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	if _, _, err := ProbeHostKey(context.Background(), host, port, 0); err == nil {
		t.Error("expected an error connecting to a closed port")
	}
}
