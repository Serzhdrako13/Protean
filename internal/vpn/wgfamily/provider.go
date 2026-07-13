// Package wgfamily implements the shared plumbing behind WireGuard and
// AmneziaWG, which speak near-identical CLIs (wg/wg-quick vs awg/awg-quick)
// and config file formats. Each concrete provider only supplies the binary
// names, interface, and config path; this package does the actual work.
package wgfamily

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"protean/internal/sshexec"
	"protean/internal/vpn"
)

// SSHRunner is the subset of *sshexec.Client that wg-family providers need.
// Declaring it here (rather than depending on the concrete client) keeps the
// provider testable with an in-memory fake.
type SSHRunner interface {
	Run(ctx context.Context, cmd string) (string, error)
	ReadFile(ctx context.Context, path string) (string, error)
	WriteFile(ctx context.Context, path, content string) error
	InterfaceExists(ctx context.Context, iface string) bool
}

// compile-time assertion that the real client satisfies the interface.
var _ SSHRunner = (*sshexec.Client)(nil)

// Options configures a wg-family provider instance.
type Options struct {
	// ProviderName is the backend TYPE reported by Type(), e.g. "wireguard"
	// or "amneziawg".
	ProviderName string
	// InstanceID is the unique instance identifier reported by Name() (URL +
	// DB key). Defaults to Interface when empty.
	InstanceID string
	// Interface is the network interface name, e.g. "wg0" or "awg0".
	Interface string
	// ConfPath is the absolute path to the wg-quick style config file on
	// the host.
	ConfPath string
	// Binary is the show/set CLI, "wg" or "awg".
	Binary string
	// ServiceName is the systemd unit to restart on server-config changes
	// that require a full interface reload, e.g. "wg-quick@wg0".
	ServiceName string
	// PublicHost is the VPS's public IP/hostname, used to build the
	// Endpoint reported in ServerStatus.
	PublicHost string
	// HandshakeOnlineWindow is how recent a handshake must be for a peer
	// to be considered online. Defaults to 180s (the wg-quick convention).
	HandshakeOnlineWindow time.Duration

	SSH SSHRunner

	// Backup, if set, receives a snapshot of the current config just before
	// each overwrite, so a bad edit can be recovered. Optional.
	Backup BackupSink
}

// BackupSink stores a pre-write snapshot of an interface config. Implemented
// by the store; kept as an interface so wgfamily stays DB-agnostic.
type BackupSink interface {
	SaveConfBackup(ctx context.Context, provider, content string) error
}

type Provider struct {
	opts Options
	// mu serializes every operation that reads or read-modify-writes the
	// config file, so concurrent admin actions (or an action overlapping the
	// dashboard's status poll) can't lose a peer to a last-write-wins race or
	// observe a half-written file. The panel is single-instance, so an
	// in-process lock per interface is sufficient.
	mu sync.Mutex
}

func New(opts Options) *Provider {
	if opts.HandshakeOnlineWindow == 0 {
		opts.HandshakeOnlineWindow = 180 * time.Second
	}
	if opts.InstanceID == "" {
		opts.InstanceID = opts.Interface
	}
	return &Provider{opts: opts}
}

func (p *Provider) Name() string { return p.opts.InstanceID }
func (p *Provider) Type() string { return p.opts.ProviderName }

func (p *Provider) showDump(ctx context.Context) (DumpInterface, []DumpPeer, bool, error) {
	out, err := p.opts.SSH.Run(ctx, fmt.Sprintf("sudo %s show %s dump", p.opts.Binary, p.opts.Interface))
	if err != nil {
		// Distinguish "interface is down/absent" (an expected state the UI
		// renders as DOWN) from a genuine failure, by probing for the
		// interface rather than matching locale-dependent error text.
		if !p.opts.SSH.InterfaceExists(ctx, p.opts.Interface) {
			return DumpInterface{}, nil, false, nil
		}
		return DumpInterface{}, nil, false, fmt.Errorf("show dump: %w", err)
	}
	iface, peers, err := ParseDump(out)
	if err != nil {
		return DumpInterface{}, nil, false, err
	}
	return iface, peers, true, nil
}

func (p *Provider) readConf(ctx context.Context) (*ConfFile, error) {
	raw, err := p.opts.SSH.ReadFile(ctx, p.opts.ConfPath)
	if err != nil {
		return nil, fmt.Errorf("read conf: %w", err)
	}
	return ParseConf(raw), nil
}

// writeConf overwrites the on-host config, returning the previous file
// contents (empty if it couldn't be read) so a caller can roll back after a
// later failure. The previous content is also saved as a backup, best-effort.
func (p *Provider) writeConf(ctx context.Context, conf *ConfFile) (prev string, err error) {
	// Snapshot the current on-host config before overwriting, so a bad edit
	// (or a first edit that normalizes a hand-maintained file) is
	// recoverable. Best-effort: a backup failure must not block the write.
	if cur, rerr := p.opts.SSH.ReadFile(ctx, p.opts.ConfPath); rerr == nil {
		prev = cur
		if p.opts.Backup != nil {
			if berr := p.opts.Backup.SaveConfBackup(ctx, p.Name(), cur); berr != nil {
				slog.Warn("wgfamily: config backup failed (continuing)", "path", p.opts.ConfPath, "err", berr)
			}
		}
	}
	if err := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, conf.Render()); err != nil {
		return prev, fmt.Errorf("write conf: %w", err)
	}
	return prev, nil
}

// writeConfAndApply writes the config then applies the peer to the live
// interface, rolling the config file back to its previous contents if the live
// apply fails -- so the on-disk config and the running interface can't diverge.
func (p *Provider) writeConfAndApply(ctx context.Context, conf *ConfFile, pub string, allowedIPs []string, keepalive int) error {
	prev, err := p.writeConf(ctx, conf)
	if err != nil {
		return err
	}
	if err := p.applyPeerLive(ctx, pub, allowedIPs, keepalive); err != nil {
		if prev != "" {
			if rbErr := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, prev); rbErr != nil {
				slog.Error("wgfamily: apply-live failed AND config rollback failed; on-disk config may diverge from live state",
					"path", p.opts.ConfPath, "applyErr", err, "rollbackErr", rbErr)
			}
		}
		return fmt.Errorf("apply live (config rolled back): %w", err)
	}
	return nil
}

func (p *Provider) Status(ctx context.Context) (vpn.ServerStatus, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	iface, peers, up, err := p.showDump(ctx)
	if err != nil {
		return vpn.ServerStatus{}, err
	}
	status := vpn.ServerStatus{Provider: p.Name(), Up: up}
	if !up {
		return status, nil
	}

	if conf, err := p.readConf(ctx); err == nil {
		status.Address, _ = conf.InterfaceGet("Address")
		status.DNS, _ = conf.InterfaceGet("DNS")
		if mtu, ok := conf.InterfaceGet("MTU"); ok {
			status.MTU, _ = strconv.Atoi(mtu)
		}
		status.Extra = map[string]string{}
		for _, kv := range conf.InterfaceOpts {
			switch kv.Key {
			case "PrivateKey", "Address", "ListenPort", "DNS", "MTU", "PostUp", "PostDown", "PreUp", "PreDown":
				// surfaced elsewhere (dedicated fields) or panel-managed
				// plumbing that shouldn't appear as an editable extra
			default:
				status.Extra[kv.Key] = kv.Value
			}
		}
	}

	threshold := time.Now().Add(-p.opts.HandshakeOnlineWindow)
	for _, peer := range peers {
		status.TotalRxBytes += peer.RxBytes
		status.TotalTxBytes += peer.TxBytes
		if !peer.LatestHandshake.IsZero() && peer.LatestHandshake.After(threshold) {
			status.PeersOnline++
		}
	}
	status.PeerCount = len(peers)
	status.PublicKey = iface.PublicKey
	status.ListenPort = iface.ListenPort
	if p.opts.PublicHost != "" {
		status.Endpoint = fmt.Sprintf("%s:%d", p.opts.PublicHost, iface.ListenPort)
	}
	return status, nil
}

func (p *Provider) ListPeers(ctx context.Context) ([]vpn.Peer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, dumpPeers, up, err := p.showDump(ctx)
	if err != nil {
		return nil, err
	}
	if !up {
		return nil, fmt.Errorf("interface %s is down", p.opts.Interface)
	}

	conf, err := p.readConf(ctx)
	if err != nil {
		return nil, err
	}

	threshold := time.Now().Add(-p.opts.HandshakeOnlineWindow)
	peers := make([]vpn.Peer, 0, len(dumpPeers))
	for _, dp := range dumpPeers {
		name := ""
		if cp := conf.FindPeer(dp.PublicKey); cp != nil {
			name = cp.Name
		}
		peers = append(peers, vpn.Peer{
			ID:                  dp.PublicKey,
			Provider:            p.Name(),
			Name:                name,
			PublicKey:           dp.PublicKey,
			AllowedIPs:          dp.AllowedIPs,
			Endpoint:            dp.Endpoint,
			LastHandshake:       dp.LatestHandshake,
			RxBytes:             dp.RxBytes,
			TxBytes:             dp.TxBytes,
			PersistentKeepalive: dp.PersistentKeepalive,
			Online:              !dp.LatestHandshake.IsZero() && dp.LatestHandshake.After(threshold),
		})
	}
	return peers, nil
}

func (p *Provider) AddPeer(ctx context.Context, spec vpn.PeerSpec) (vpn.NewPeerResult, error) {
	if err := validateName(spec.Name); err != nil {
		return vpn.NewPeerResult{}, err
	}
	if err := validateAllowedIPs(spec.AllowedIPs); err != nil {
		return vpn.NewPeerResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return vpn.NewPeerResult{}, fmt.Errorf("generate keys: %w", err)
	}

	conf, err := p.readConf(ctx)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	if conf.FindPeer(pub) != nil {
		return vpn.NewPeerResult{}, fmt.Errorf("generated key collides with an existing peer, retry")
	}

	conf.AddPeer(ConfPeer{Name: spec.Name, Opts: peerOpts(pub, spec)})
	if err := p.writeConfAndApply(ctx, conf, pub, spec.AllowedIPs, spec.PersistentKeepalive); err != nil {
		return vpn.NewPeerResult{}, err
	}

	return vpn.NewPeerResult{
		Peer: vpn.Peer{
			ID:                  pub,
			Provider:            p.Name(),
			Name:                spec.Name,
			PublicKey:           pub,
			AllowedIPs:          spec.AllowedIPs,
			PersistentKeepalive: spec.PersistentKeepalive,
		},
		PrivateKey: priv,
	}, nil
}

// AddConfiguredPeer adds a peer with an already-known public key (no key
// generation), used to re-enable a previously disabled peer. Idempotent-ish:
// errors if the peer is already present.
func (p *Provider) AddConfiguredPeer(ctx context.Context, publicKey string, spec vpn.PeerSpec) error {
	if err := validateName(spec.Name); err != nil {
		return err
	}
	if err := validateAllowedIPs(spec.AllowedIPs); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}
	if conf.FindPeer(publicKey) != nil {
		return fmt.Errorf("peer %s already present", publicKey)
	}
	conf.AddPeer(ConfPeer{Name: spec.Name, Opts: peerOpts(publicKey, spec)})
	return p.writeConfAndApply(ctx, conf, publicKey, spec.AllowedIPs, spec.PersistentKeepalive)
}

func (p *Provider) UpdatePeer(ctx context.Context, id string, spec vpn.PeerSpec) error {
	if err := validateName(spec.Name); err != nil {
		return err
	}
	if err := validateAllowedIPs(spec.AllowedIPs); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}
	if conf.FindPeer(id) == nil {
		return fmt.Errorf("peer %s not found", id)
	}

	conf.ReplacePeer(id, ConfPeer{Name: spec.Name, Opts: peerOpts(id, spec)})
	return p.writeConfAndApply(ctx, conf, id, spec.AllowedIPs, spec.PersistentKeepalive)
}

func (p *Provider) RemovePeer(ctx context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}
	if !conf.RemovePeer(id) {
		return fmt.Errorf("peer %s not found", id)
	}
	if _, err := p.writeConf(ctx, conf); err != nil {
		return err
	}
	cmd := fmt.Sprintf("sudo %s set %s peer %s remove", p.opts.Binary, p.opts.Interface, sshexec.ShellQuote(id))
	_, err = p.opts.SSH.Run(ctx, cmd)
	return err
}

// RotatePeerKey generates a fresh keypair for an existing peer, keeping its
// name, AllowedIPs and keepalive. Useful for adopting peers that were created
// outside the panel (and whose private key it therefore never had): after
// rotation the panel holds the new key and can hand out the client config.
// The old key stops working immediately -- the old client must load the new
// config.
func (p *Provider) RotatePeerKey(ctx context.Context, oldPubKey string) (vpn.NewPeerResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conf, err := p.readConf(ctx)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	old := conf.FindPeer(oldPubKey)
	if old == nil {
		return vpn.NewPeerResult{}, fmt.Errorf("peer %s not found", oldPubKey)
	}

	// Preserve the peer's existing identity/routing.
	name := old.Name
	allowed := []string{}
	if v, ok := getOpt(old.Opts, "AllowedIPs"); ok && v != "" {
		for _, a := range strings.Split(v, ",") {
			allowed = append(allowed, strings.TrimSpace(a))
		}
	}
	keepalive := 0
	if v, ok := getOpt(old.Opts, "PersistentKeepalive"); ok {
		keepalive, _ = strconv.Atoi(v)
	}

	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return vpn.NewPeerResult{}, fmt.Errorf("generate keys: %w", err)
	}
	if conf.FindPeer(pub) != nil {
		return vpn.NewPeerResult{}, fmt.Errorf("generated key collides with an existing peer, retry")
	}

	spec := vpn.PeerSpec{Name: name, AllowedIPs: allowed, PersistentKeepalive: keepalive}
	conf.RemovePeer(oldPubKey)
	conf.AddPeer(ConfPeer{Name: name, Opts: peerOpts(pub, spec)})
	prev, err := p.writeConf(ctx, conf)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	rollback := func(cause error) error {
		if prev != "" {
			if rbErr := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, prev); rbErr != nil {
				slog.Error("wgfamily: rotate live-apply failed AND config rollback failed; on-disk config may diverge",
					"path", p.opts.ConfPath, "cause", cause, "rollbackErr", rbErr)
			}
		}
		return cause
	}

	// Live: drop the old peer, add the new one.
	if _, err := p.opts.SSH.Run(ctx, fmt.Sprintf("sudo %s set %s peer %s remove",
		p.opts.Binary, p.opts.Interface, sshexec.ShellQuote(oldPubKey))); err != nil {
		return vpn.NewPeerResult{}, rollback(fmt.Errorf("remove old peer live (config rolled back): %w", err))
	}
	if err := p.applyPeerLive(ctx, pub, allowed, keepalive); err != nil {
		return vpn.NewPeerResult{}, rollback(fmt.Errorf("apply new peer live (config rolled back): %w", err))
	}

	return vpn.NewPeerResult{
		Peer: vpn.Peer{
			ID: pub, Provider: p.Name(), Name: name,
			PublicKey: pub, AllowedIPs: allowed, PersistentKeepalive: keepalive,
		},
		PrivateKey: priv,
	}, nil
}

func (p *Provider) UpdateServerConfig(ctx context.Context, cfg vpn.ServerConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}
	if cfg.ListenPort > 0 {
		conf.InterfaceSet("ListenPort", strconv.Itoa(cfg.ListenPort))
	}
	if cfg.Address != "" {
		conf.InterfaceSet("Address", cfg.Address)
	}
	if cfg.DNS != "" {
		conf.InterfaceSet("DNS", cfg.DNS)
	}
	if cfg.MTU > 0 {
		conf.InterfaceSet("MTU", strconv.Itoa(cfg.MTU))
	} else {
		conf.InterfaceUnset("MTU")
	}
	for k, v := range cfg.Extra {
		conf.InterfaceSet(k, v)
	}
	if _, err := p.writeConf(ctx, conf); err != nil {
		return err
	}
	// Listen port / address / key changes only take effect after the
	// interface is fully reloaded.
	return p.restart(ctx)
}

// RestoreConf overwrites the interface config with raw content (e.g. a
// backup snapshot) and reloads the interface. The current config is itself
// snapshotted first (via writeConf's backup hook is bypassed here since we
// write raw, so back up explicitly).
func (p *Provider) RestoreConf(ctx context.Context, content string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.opts.Backup != nil {
		if cur, err := p.opts.SSH.ReadFile(ctx, p.opts.ConfPath); err == nil {
			_ = p.opts.Backup.SaveConfBackup(ctx, p.Name(), cur)
		}
	}
	if err := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, content); err != nil {
		return fmt.Errorf("write conf: %w", err)
	}
	return p.restart(ctx)
}

// ForwardingEnabled reports whether the panel-managed FORWARD rules are
// present in the interface config.
func (p *Provider) ForwardingEnabled(ctx context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conf, err := p.readConf(ctx)
	if err != nil {
		return false, err
	}
	return conf.HasManagedForwarding(), nil
}

// EnableForwarding writes the panel-managed FORWARD rules into the config and
// restarts the interface so they take effect. This briefly disconnects
// clients (a full interface reload), which is why it's an explicit action
// rather than something done silently on every peer change.
func (p *Provider) EnableForwarding(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}
	conf.SetManagedNetworking(p.firewallBackend(ctx), true, false, "", "")
	if _, err := p.writeConf(ctx, conf); err != nil {
		return err
	}
	return p.restart(ctx)
}

// firewallBackend picks iptables (present on modern distros via the nft shim)
// or native nftables when iptables is absent.
func (p *Provider) firewallBackend(ctx context.Context) FirewallBackend {
	if _, err := p.opts.SSH.Run(ctx, "command -v iptables"); err == nil {
		return BackendIptables
	}
	return BackendNft
}

// EgressEnabled reports whether internet-egress NAT is currently configured.
func (p *Provider) EgressEnabled(ctx context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conf, err := p.readConf(ctx)
	if err != nil {
		return false, err
	}
	return conf.HasManagedNAT(), nil
}

// ApplyNetworking sets the host-side networking for this interface: FORWARD
// rules are always on (the VPN needs to route), and internet-egress
// MASQUERADE is added/removed per egress. Restarts the interface to apply.
func (p *Provider) ApplyNetworking(ctx context.Context, egress bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	conf, err := p.readConf(ctx)
	if err != nil {
		return err
	}

	tunnelCIDR := ""
	if addr, ok := conf.InterfaceGet("Address"); ok {
		// Address may be a dual-stack comma list; NAT the first (IPv4) net.
		if _, ipnet, err := net.ParseCIDR(vpn.FirstCIDR(addr)); err == nil {
			tunnelCIDR = ipnet.String()
		}
	}
	wan := ""
	if egress {
		wan, err = p.detectWAN(ctx)
		if err != nil {
			return fmt.Errorf("detect WAN interface for egress: %w", err)
		}
	}
	conf.SetManagedNetworking(p.firewallBackend(ctx), true, egress, tunnelCIDR, wan)

	if _, err := p.writeConf(ctx, conf); err != nil {
		return err
	}
	return p.restart(ctx)
}

// detectWAN returns the host's default-route interface, used as the egress
// interface for MASQUERADE.
func (p *Provider) detectWAN(ctx context.Context) (string, error) {
	out, err := p.opts.SSH.Run(ctx, "ip route show default")
	if err != nil {
		return "", err
	}
	// e.g. "default via 203.0.113.1 dev eth0 proto static"
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("no default route found")
}

func (p *Provider) restart(ctx context.Context) error {
	if _, err := vpn.NewInstaller(p.opts.SSH).Service(ctx, "restart", p.opts.ServiceName); err != nil {
		return fmt.Errorf("restart %s: %w", p.opts.ServiceName, err)
	}
	return nil
}

// EnsureServer brings this interface up for the FIRST time if (and only
// if) its config file doesn't already exist on the host: generates a
// fresh keypair, writes the [Interface] block, enables+starts the systemd
// unit. Deliberately never touches an existing file -- unlike cert-based
// providers' EnsureServer (which safely re-issues certs on every call),
// overwriting Address/PrivateKey on a wg-family interface that already has
// real peers would silently break every one of them, so this is a strict
// "first bring-up only" operation, a safe no-op on repeat calls.
//
// Existence is checked with `test -e` (not a read) so it doesn't depend on
// read permission on the file. Caveat worth flagging: a transient SSH
// failure on that check is indistinguishable from "file genuinely doesn't
// exist" and this method treats both the same way (proceeds to write) --
// every other wg-family method has the same readConf-error ambiguity, but
// they just fail the operation on it; this is the one operation where a
// false negative on "does it exist" would write a brand new file instead
// of merely erroring out.
func (p *Provider) EnsureServer(ctx context.Context, address string, listenPort int, dns, mtu string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, err := p.opts.SSH.Run(ctx, fmt.Sprintf("test -e %s", sshexec.ShellQuote(p.opts.ConfPath))); err == nil {
		return nil // already set up -- never overwrite
	}

	if address == "" {
		return fmt.Errorf("address is required to bring up a new interface")
	}
	priv, _, err := GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	cf := &ConfFile{}
	cf.InterfaceSet("PrivateKey", priv)
	cf.InterfaceSet("Address", address)
	if listenPort > 0 {
		cf.InterfaceSet("ListenPort", strconv.Itoa(listenPort))
	}
	if dns != "" {
		cf.InterfaceSet("DNS", dns)
	}
	if mtu != "" {
		cf.InterfaceSet("MTU", mtu)
	}

	if err := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, cf.Render()); err != nil {
		return fmt.Errorf("write conf: %w", err)
	}
	if _, err := vpn.NewInstaller(p.opts.SSH).Service(ctx, "enable", p.opts.ServiceName); err != nil {
		return fmt.Errorf("enable %s: %w", p.opts.ServiceName, err)
	}
	return nil
}

// ServiceName exposes the systemd unit for service-control actions.
func (p *Provider) ServiceName() string { return p.opts.ServiceName }

func (p *Provider) applyPeerLive(ctx context.Context, pubkey string, allowedIPs []string, keepalive int) error {
	args := []string{"set", p.opts.Interface, "peer", pubkey, "allowed-ips", strings.Join(allowedIPs, ",")}
	if keepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(keepalive))
	} else {
		args = append(args, "persistent-keepalive", "0")
	}
	var cmd strings.Builder
	cmd.WriteString("sudo ")
	cmd.WriteString(p.opts.Binary)
	for _, a := range args {
		cmd.WriteString(" ")
		cmd.WriteString(sshexec.ShellQuote(a))
	}
	_, err := p.opts.SSH.Run(ctx, cmd.String())
	return err
}

func peerOpts(publicKey string, spec vpn.PeerSpec) []KV {
	opts := []KV{
		{Key: "PublicKey", Value: publicKey},
		{Key: "AllowedIPs", Value: strings.Join(spec.AllowedIPs, ", ")},
	}
	if spec.PersistentKeepalive > 0 {
		opts = append(opts, KV{Key: "PersistentKeepalive", Value: strconv.Itoa(spec.PersistentKeepalive)})
	}
	for k, v := range spec.Extra {
		opts = append(opts, KV{Key: k, Value: v})
	}
	return opts
}

func validateAllowedIPs(ips []string) error {
	if len(ips) == 0 {
		return fmt.Errorf("allowed-ips must not be empty")
	}
	for _, ip := range ips {
		if _, _, err := net.ParseCIDR(ip); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", ip, err)
		}
	}
	return nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if len(name) > 100 {
		return fmt.Errorf("name too long (max 100 chars)")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("name must not contain control characters")
		}
	}
	return nil
}
