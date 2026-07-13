package sshexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// errHostKeyCaptured aborts the SSH handshake the instant the host key is
// seen, deliberately BEFORE any authentication is attempted -- ProbeHostKey
// needs no valid credentials at all, since the host key is presented during
// key exchange, well before auth.
var errHostKeyCaptured = errors.New("host key captured")

// ProbeHostKey connects just far enough to observe the SSH host key
// currently presented at host:port, then aborts -- for the panel's
// "fetch current host key" action, so an admin can see (and choose to
// pin) what's actually being offered without ever SSHing in by hand.
// This does NOT verify anything -- exactly like running ssh-keyscan, the
// result must still be confirmed out-of-band before trusting it, since
// this connection is just as exposed to a MITM as any other.
func ProbeHostKey(ctx context.Context, host string, port int, timeout time.Duration) (authorizedKeyLine, fingerprint string, err error) {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", "", fmt.Errorf("dial %s: %w", addr, err)
	}
	defer netConn.Close()

	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:    "protean-hostkey-probe",
		Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		},
	}
	_, _, _, dialErr := ssh.NewClientConn(netConn, addr, cfg)
	if captured == nil {
		return "", "", fmt.Errorf("ssh handshake %s: %w", addr, dialErr)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(captured))), ssh.FingerprintSHA256(captured), nil
}
