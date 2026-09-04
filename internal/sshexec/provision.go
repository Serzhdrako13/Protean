package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// GenerateKeyPair creates a fresh ed25519 SSH keypair: the private key in
// OpenSSH PEM (to store, encrypted) and the public key as an authorized_keys
// line (to install on the host).
func GenerateKeyPair(comment string) (privPEM []byte, pubLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", err
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return pem.EncodeToMemory(block), line, nil
}

// dialPassword opens an SSH connection using password auth (one-time). The
// caller closes the returned client.
func dialPassword(ctx context.Context, cfg Config, password string) (*ssh.Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	hostKeyCallback, err := buildHostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}
	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         cfg.Timeout,
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: cfg.Timeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientCfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("password auth to %s failed: %w", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// dialKey opens an SSH connection using private-key auth (one-time) -- the
// bootstrap-identity sibling of dialPassword, used when the admin supplies
// an existing private key for root or an existing sudo user instead of a
// password. The caller closes the returned client.
func dialKey(ctx context.Context, cfg Config, keyPEM []byte) (*ssh.Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse bootstrap key: %w", err)
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
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: cfg.Timeout}
	netConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientCfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("key auth to %s failed: %w", addr, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

var validUnixUser = func(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// BootstrapAuth is the one-time credential used to connect to the bootstrap
// identity (root or an existing sudo user). Exactly one of Password or
// KeyPEM must be set. Neither is ever persisted -- used only for the single
// connection BootstrapHost makes, then discarded.
type BootstrapAuth struct {
	Password string
	KeyPEM   []byte
}

// BootstrapHost provisions a host from the UI over a one-time credential for
// a root or existing-sudo-user bootstrap identity (cfg.User): it creates
// serviceUser if it doesn't already exist, or just grants it rights if it
// does; installs the panel's own generated SSH key for it; places the
// root-owned installer script; writes a narrow NOPASSWD sudoers rule scoped
// to that installer plus the wg/awg/swanctl binaries; and makes the VPN
// config dirs writable by it. auth is used only for this one connection and
// is never stored -- cfg.User and serviceUser may be the same account (an
// existing sudo user reused directly) or different (bootstrapping via root,
// or via a different existing sudo user, to stand up a dedicated account).
// BootstrapHost's return value is the provisioning script's combined output
// (whose first line is PROTEAN_USER_CREATED or PROTEAN_USER_EXISTED, so
// callers can report which happened), and an error if anything failed.
func BootstrapHost(ctx context.Context, cfg Config, auth BootstrapAuth, serviceUser, pubLine string, installer []byte, installerPath string) (string, error) {
	if !validUnixUser(cfg.User) {
		return "", fmt.Errorf("invalid bootstrap SSH user %q", cfg.User)
	}
	if !validUnixUser(serviceUser) {
		return "", fmt.Errorf("invalid service account name %q", serviceUser)
	}

	var client *ssh.Client
	var err error
	switch {
	case auth.Password != "":
		client, err = dialPassword(ctx, cfg, auth.Password)
	case len(auth.KeyPEM) > 0:
		client, err = dialKey(ctx, cfg, auth.KeyPEM)
	default:
		return "", fmt.Errorf("bootstrap requires a password or private key")
	}
	if err != nil {
		return "", err
	}
	defer client.Close()

	b64 := base64.StdEncoding.EncodeToString(installer)
	script := provisionScript(serviceUser, installerPath, b64, pubLine)

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	if cfg.User == "root" {
		out, err := sess.CombinedOutput("sh -c " + ShellQuote(script))
		if err != nil {
			return "", fmt.Errorf("host bootstrap failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}

	if auth.Password != "" {
		// -k: ignore any cached credential; -p '': no prompt text on stderr.
		sess.Stdin = strings.NewReader(auth.Password + "\n") // consumed by sudo -S
		out, err := sess.CombinedOutput("sudo -k -S -p '' sh -c " + ShellQuote(script))
		if err != nil {
			return "", fmt.Errorf("host bootstrap (does %s have sudo?): %w (%s)", cfg.User, err, strings.TrimSpace(string(out)))
		}
		return string(out), nil
	}

	// Key auth for a non-root bootstrap identity: there's no password to
	// feed sudo -S, so this only works if the account already has
	// passwordless sudo configured.
	out, err := sess.CombinedOutput("sudo -n sh -c " + ShellQuote(script))
	if err != nil {
		return "", fmt.Errorf("host bootstrap failed -- %s needs passwordless sudo to bootstrap via a key (use a password or root instead): %w (%s)",
			cfg.User, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// provisionScript is the fixed root-side provisioning script run over a
// bootstrap connection. serviceUser/installerPath are validated to safe
// charsets by the caller; b64 is base64 (no quotes); pubLine is
// shell-quoted explicitly since it may contain spaces/comments -- so the
// whole thing is safe wrapped in the single quotes BootstrapHost uses.
func provisionScript(serviceUser, installerPath, b64, pubLine string) string {
	dir := installerPath[:strings.LastIndexByte(installerPath, '/')]
	// /etc/openvpn itself (not just .../server below it): most distros
	// leave this world-traversable, but ALT Linux's openvpn package
	// creates it as 750 root:openvpn -- confirmed live, protean isn't in
	// that group, so it couldn't even traverse into its own (correctly
	// owned) server/ccd subdirectories underneath. Listing it here too
	// keeps the fix general rather than distro-special-cased.
	confDirs := "/etc/wireguard /etc/amnezia/amneziawg /etc/openvpn /etc/openvpn/server /etc/openvpn/server/ccd " +
		"/etc/swanctl /etc/swanctl/x509 /etc/swanctl/x509ca /etc/swanctl/private /etc/swanctl/conf.d " +
		"/etc/swanctl/x509crl /usr/local/etc/xray"
	quotedUser := ShellQuote(serviceUser)
	quotedLine := ShellQuote(strings.TrimSpace(pubLine))

	var b strings.Builder
	b.WriteString("set -e\n")

	// 1) Create the service account only if it doesn't already exist --
	//    reusing an existing one (e.g. the bootstrap identity itself) is
	//    just as valid as standing up a brand new dedicated account.
	b.WriteString("if id -u " + quotedUser + " >/dev/null 2>&1; then\n")
	b.WriteString("  echo PROTEAN_USER_EXISTED\n")
	b.WriteString("else\n")
	b.WriteString("  useradd -m -s /bin/bash " + quotedUser + "\n")
	b.WriteString("  echo PROTEAN_USER_CREATED\n")
	b.WriteString("fi\n")

	// 2) Lock the password unconditionally, regardless of distro useradd
	//    defaults -- this account is key-only, same as every other server
	//    the panel manages.
	b.WriteString("usermod -L " + quotedUser + "\n")

	// 2b) ALT Linux gates /usr/bin/sudo execution to root+wheel (mode
	//     4750 root:wheel, not world-executable like every other distro
	//     here) -- confirmed live. Without wheel membership the account
	//     can't even invoke sudo, independent of its sudoers rule being
	//     correct. `-a` (append) preserves any other group membership;
	//     a no-op everywhere the group doesn't exist.
	b.WriteString("getent group wheel >/dev/null 2>&1 && usermod -aG wheel " + quotedUser + " || true\n")

	// 3) Install the panel's own key into the account's real home,
	//    resolved via getent (not `~`, which would resolve to the
	//    *bootstrap* identity's home when it differs from serviceUser).
	//    Idempotent so a bootstrap retry never duplicates the line.
	b.WriteString("home=\"$(getent passwd " + quotedUser + " | cut -d: -f6)\"\n")
	b.WriteString("install -d -m 700 -o " + quotedUser + " -g " + quotedUser + " \"$home/.ssh\"\n")
	b.WriteString("grep -qxF " + quotedLine + " \"$home/.ssh/authorized_keys\" 2>/dev/null || printf '%s\\n' " +
		quotedLine + " >> \"$home/.ssh/authorized_keys\"\n")
	b.WriteString("chown " + quotedUser + ":" + quotedUser + " \"$home/.ssh/authorized_keys\" && chmod 600 \"$home/.ssh/authorized_keys\"\n")

	// 4) Root-owned installer.
	b.WriteString("install -d -m 755 " + dir + "\n")
	b.WriteString("echo " + b64 + " | base64 -d > " + installerPath + "\n")
	b.WriteString("chown root:root " + installerPath + " && chmod 755 " + installerPath + "\n")

	// 5) Narrow sudoers: only the audited installer script (which itself
	//    validates every action/unit/provider it's given -- see
	//    scripts/protean-installer.sh's VALID_ACTION/VALID_UNIT) plus the
	//    direct peer-management binaries that have no installer-script
	//    equivalent. Deliberately no blanket `systemctl` grant: GTFOBins
	//    lists several ways a bare `sudo systemctl` escalates to a root
	//    shell (pager/editor spawn, `systemctl link` of an attacker unit).
	b.WriteString("cat > /etc/sudoers.d/protean <<'WGP'\n")
	// swanctl lives at /usr/sbin/swanctl on every real Debian-family
	// distro (confirmed via `dpkg -L strongswan-swanctl` on both a fresh
	// Debian 12 e2e-lab container and a real Ubuntu 24.04 host) -- NOT
	// /usr/bin, unlike wg/awg. Granting the wrong path here doesn't error
	// at bootstrap time; it silently makes every `sudo swanctl ...` call
	// (CRL reload, session listing) prompt for a password instead of
	// running, which then fails outright since there's no TTY/password to
	// give it. Found live via the e2e lab (test/e2elab) -- a genuinely
	// fresh host is what finally exercised this path end-to-end; earlier
	// live testing against an aging host masked it behind an unrelated
	// stale-file-permission failure that returned first.
	// wg/awg scoped to `show *`/`set *` (the only shapes internal/vpn/
	// wgfamily ever runs) rather than the bare binary -- a bare grant
	// would also cover subcommands this panel never needs, no upside.
	// swanctl scoped to the two EXACT commands internal/vpn/ikev2 ever
	// runs (--list-sas, --load-all -- neither takes variable arguments at
	// all), tighter than a wildcard since none is needed. Found live via
	// an Opus-driven audit 2026-09-04, alongside similar narrowing in
	// scripts/setup-host.sh's own sudoers generation.
	b.WriteString(serviceUser + " ALL=(root) NOPASSWD: " + installerPath +
		", /usr/bin/wg show *, /usr/bin/wg set *, /usr/bin/awg show *, /usr/bin/awg set *, " +
		"/usr/sbin/swanctl --list-sas, /usr/sbin/swanctl --load-all\n")
	b.WriteString("WGP\n")
	// 0400 not 0440: a subset of the same permission (root-read-only; the
	// file is root:root, so the dropped group-read bit changes nothing
	// real), and required outright on ALT Linux -- its sudo refuses to
	// run at all if any file under sudoers.d fails a strict 0400 check,
	// confirmed live.
	b.WriteString("chmod 400 /etc/sudoers.d/protean\n")
	b.WriteString("visudo -cf /etc/sudoers.d/protean\n")

	// 6) Config dirs writable by the service account (it writes confs
	//    without sudo). `install -d` only sets ownership on the directory
	//    entry itself -- on a host being ADOPTED with an already-configured
	//    VPN, these dirs can already contain root-owned files (CA/CRL/conf
	//    from before this service account existed), and an in-place
	//    overwrite (`cat > file`, see sshexec.Client.WriteFile) needs write
	//    permission on the file itself, not just the directory. `chown -R`
	//    so pre-existing content becomes writable too, not just anything
	//    created from now on. Safe: every dir in confDirs is exclusively
	//    VPN config, nothing shared with unrelated files.
	b.WriteString("for d in " + confDirs + "; do install -d -m 750 -o " + quotedUser + " \"$d\"; chown -R " +
		quotedUser + ":" + quotedUser + " \"$d\"; done\n")
	return b.String()
}
