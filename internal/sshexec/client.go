// Package sshexec provides a small reconnecting SSH client used to run
// commands and read/write files on the VPN host.
package sshexec

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Config struct {
	Host string
	Port int
	User string
	// KeyPath reads the SSH private key from disk. KeyPEM supplies it directly
	// (e.g. decrypted from the DB for a UI-managed server); KeyPEM wins.
	KeyPath string
	KeyPEM  []byte
	Timeout time.Duration
	// CmdTimeout bounds a single remote command. It backstops a live-but-stuck
	// host so a command can't hang forever; request-context cancellation
	// interrupts sooner. Default 30s.
	CmdTimeout time.Duration

	// HostKey, if set, is the host's public key in authorized_keys line
	// format (e.g. "ssh-ed25519 AAAA..."). When present it's pinned
	// strictly -- this is the recommended production setting, populated by
	// setup-host.sh into the panel's environment.
	HostKey string
	// KnownHostsPath, if set, points at an OpenSSH known_hosts file used to
	// verify (and, on first contact, learn) the host key. Takes effect only
	// when HostKey is empty.
	KnownHostsPath string
}

// Client is a reconnecting SSH client. It is safe for concurrent use; each
// Run/ReadFile/WriteFile call opens its own session over a shared connection.
type Client struct {
	cfg       Config
	clientCfg *ssh.ClientConfig
	mu        sync.Mutex
	conn      *ssh.Client

	// command metrics (atomic)
	cmds        atomic.Uint64
	cmdErrs     atomic.Uint64
	lastLatency atomic.Int64 // nanoseconds of the last command
}

// Stats is a snapshot of the client's command counters, exposed for metrics.
type Stats struct {
	Commands    uint64
	Errors      uint64
	LastLatency time.Duration
}

// Stats returns the current command counters.
func (c *Client) Stats() Stats {
	return Stats{
		Commands:    c.cmds.Load(),
		Errors:      c.cmdErrs.Load(),
		LastLatency: time.Duration(c.lastLatency.Load()),
	}
}

// Ping checks host reachability with a trivial command, for health checks.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Run(ctx, "true")
	return err
}

func New(cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.CmdTimeout == 0 {
		cfg.CmdTimeout = 30 * time.Second
	}
	key := cfg.KeyPEM
	if len(key) == 0 {
		var err error
		key, err = os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read ssh key: %w", err)
		}
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}

	hostKeyCallback, err := buildHostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	}
	return &Client{cfg: cfg, clientCfg: clientCfg}, nil
}

// buildHostKeyCallback chooses how the host key is verified, in order of
// preference: a pinned key from config (strict), an OpenSSH known_hosts
// file (strict, learnable out of band), or trust-on-first-use kept in
// memory for the process lifetime. TOFU is a fallback, not the default:
// it protects every connection after the first and logs the fingerprint so
// the operator can pin it -- strictly better than ignoring the host key.
func buildHostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	if cfg.HostKey != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, fmt.Errorf("parse SSH_HOST_KEY: %w", err)
		}
		return ssh.FixedHostKey(pub), nil
	}
	if cfg.KnownHostsPath != "" {
		cb, err := knownhosts.New(cfg.KnownHostsPath)
		if err != nil {
			return nil, fmt.Errorf("load known_hosts %s: %w", cfg.KnownHostsPath, err)
		}
		return cb, nil
	}
	return tofuCallback(), nil
}

// tofuCallback pins the first host key it sees and rejects any later
// mismatch for the process lifetime.
func tofuCallback() ssh.HostKeyCallback {
	var (
		mu     sync.Mutex
		pinned ssh.PublicKey
	)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		if pinned == nil {
			pinned = key
			slog.Warn("sshexec: trusting host key on first use; pin it via SSH_HOST_KEY",
				"host", hostname,
				"fingerprint", ssh.FingerprintSHA256(key),
				// MarshalAuthorizedKey already includes the "ssh-ed25519 "
				// type prefix -- prepending key.Type() again here used to
				// duplicate it, producing a line that wouldn't parse back
				// via ssh.ParseAuthorizedKey if copied as-is.
				"pin", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
			return nil
		}
		if !bytes.Equal(pinned.Marshal(), key.Marshal()) {
			return fmt.Errorf("host key mismatch for %s: got %s, pinned a different key earlier (possible MITM)",
				hostname, ssh.FingerprintSHA256(key))
		}
		return nil
	}
}

func (c *Client) addr() string {
	return net.JoinHostPort(c.cfg.Host, fmt.Sprintf("%d", c.cfg.Port))
}

// connection returns a live SSH connection, reconnecting if necessary. The
// context bounds the dial/handshake on a reconnect.
func (c *Client) connection(ctx context.Context) (*ssh.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Cheap liveness check: open and immediately close a session.
		if sess, err := c.conn.NewSession(); err == nil {
			sess.Close()
			return c.conn, nil
		}
		c.conn.Close()
		c.conn = nil
	}

	d := net.Dialer{Timeout: c.cfg.Timeout}
	netConn, err := d.DialContext(ctx, "tcp", c.addr())
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.addr(), err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, c.addr(), c.clientCfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", c.addr(), err)
	}
	c.conn = ssh.NewClient(sshConn, chans, reqs)
	return c.conn, nil
}

// Run executes a command on the remote host and returns its stdout. A
// non-zero exit status or stderr output is surfaced as an error. The command
// is interrupted when ctx is cancelled or the per-command timeout elapses.
func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	start := time.Now()
	c.cmds.Add(1)
	out, err := c.run(ctx, cmd)
	c.lastLatency.Store(int64(time.Since(start)))
	if err != nil {
		c.cmdErrs.Add(1)
	}
	return out, err
}

func (c *Client) run(ctx context.Context, cmd string) (string, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return "", err
	}
	sess, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	cmdCtx := ctx
	if c.cfg.CmdTimeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, c.cfg.CmdTimeout)
		defer cancel()
	}

	// Force the C locale so command output and any error text the panel
	// parses are stable regardless of the host's configured locale.
	if err := sess.Start("LC_ALL=C LANG=C " + cmd); err != nil {
		return "", fmt.Errorf("start %q: %w", cmd, err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("run %q: %w (stderr: %s)", cmd, err, stderr.String())
		}
		return stdout.String(), nil
	case <-cmdCtx.Done():
		// Closing the session unblocks Wait; drain it so the goroutine exits.
		sess.Close()
		<-done
		return "", fmt.Errorf("run %q: %w", cmd, cmdCtx.Err())
	}
}

// exists reports whether a network interface is present on the host,
// distinguishing "the interface is down / absent" from "the command failed
// for some other reason" without depending on locale-specific error text.
func (c *Client) exists(ctx context.Context, iface string) bool {
	_, err := c.Run(ctx, "ip link show "+ShellQuote(iface))
	return err == nil
}

// InterfaceExists is the exported form of the interface-presence check.
func (c *Client) InterfaceExists(ctx context.Context, iface string) bool {
	return c.exists(ctx, iface)
}

// ReadFile reads a remote file via `cat`.
func (c *Client) ReadFile(ctx context.Context, path string) (string, error) {
	return c.Run(ctx, fmt.Sprintf("cat %s", ShellQuote(path)))
}

// WriteFile overwrites a remote file's contents in place via a heredoc,
// avoiding shell-escaping of content. This intentionally isn't a
// write-temp-then-rename: a rename needs write permission on the parent
// directory, whereas an in-place overwrite only needs write permission on
// the file itself -- letting the deployed permission model grant the panel
// group-write on exactly the config files it manages, nothing more.
func (c *Client) WriteFile(ctx context.Context, path string, content string) error {
	cmd := fmt.Sprintf("cat > %s <<'PROTEAN_EOF'\n%s\nPROTEAN_EOF",
		ShellQuote(path), content)
	_, err := c.Run(ctx, cmd)
	return err
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// ShellQuote wraps s in single quotes so it is passed to the remote shell as
// one literal argument, regardless of its contents.
func ShellQuote(s string) string {
	return "'" + replaceAll(s, "'", `'\''`) + "'"
}

func replaceAll(s, old, new string) string {
	return string(bytes.ReplaceAll([]byte(s), []byte(old), []byte(new)))
}
