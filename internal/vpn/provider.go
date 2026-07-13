// Package vpn defines the provider abstraction that lets the panel manage
// different VPN backends (WireGuard, AmneziaWG, OpenVPN, IKEv2) through a
// single interface.
package vpn

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNotImplemented is returned by provider stubs that have not been built
// out yet (OpenVPN, IKEv2).
var ErrNotImplemented = errors.New("provider not implemented yet")

// ServerStatus describes the current state of a VPN interface on the host.
type ServerStatus struct {
	Provider     string
	Up           bool
	PublicKey    string
	ListenPort   int
	Endpoint     string // host's public endpoint, host:port
	Address      string // interface address/CIDR
	DNS          string
	PeerCount    int
	PeersOnline  int
	TotalRxBytes uint64
	TotalTxBytes uint64
	// MTU is the interface's configured MTU, 0 if unset (OS/wg-quick
	// default, currently 1420 for WireGuard/AmneziaWG). Not every provider
	// supports reading this back -- 0 there just means "unknown", not
	// necessarily "unset".
	MTU int
	// Mssfix is OpenVPN-only: clamps TCP MSS instead of changing the tunnel
	// device MTU (OpenVPN's `mssfix` directive, a sibling of `tun-mtu`/MTU
	// above). 0 = not set.
	Mssfix int
	Extra  map[string]string // provider-specific fields (e.g. AmneziaWG obfuscation params)
}

// Peer represents a single client/site connected (or configured) on a VPN
// interface, combining live state with the friendly metadata stored in the
// config file comments.
type Peer struct {
	ID                  string // stable identifier; for wg-family this is the public key
	Provider            string
	Name                string
	PublicKey           string
	AllowedIPs          []string
	Endpoint            string // last-seen source address of the peer (often a private/grey IP)
	LastHandshake       time.Time
	RxBytes             uint64
	TxBytes             uint64
	PersistentKeepalive int
	Online              bool
	Extra               map[string]string
}

// PeerSpec is the desired state for a peer, used both for creation and
// updates.
type PeerSpec struct {
	Name                string
	AllowedIPs          []string
	PersistentKeepalive int
	Extra               map[string]string
}

// NewPeerResult is returned after creating a peer and includes the private
// key, which only exists at creation time and is never returned by
// ListPeers. Building a ready-to-use client config from this is the
// caller's responsibility (see internal/vpn/clientconfig), since it depends
// on routing policy (which subnets the client should reach) that the
// provider itself has no opinion on.
type NewPeerResult struct {
	Peer       Peer
	PrivateKey string
}

// ServerConfig is the desired state of the server-side interface.
type ServerConfig struct {
	ListenPort int
	Address    string
	DNS        string
	// MTU: 0 means "leave as-is / OS default," not "set MTU to 0" --
	// providers that support it (wg-family) unset the config line entirely
	// rather than writing MTU=0, which wg-quick would reject anyway.
	MTU int
	// Mssfix: OpenVPN-only, see ServerStatus.Mssfix. 0 = leave unset.
	Mssfix int
	Extra  map[string]string // e.g. Jc/Jmin/Jmax/S1/S2/H1-4 for AmneziaWG
}

// Provider manages one VPN backend instance on the host.
type Provider interface {
	// Name is the stable INSTANCE identifier, unique across the registry and
	// used in URLs and as the DB key -- e.g. "wg0", "wg1", "openvpn". It's a
	// single interface/instance of a type.
	Name() string

	// Type is the backend TYPE: "wireguard", "amneziawg", "openvpn",
	// "ikev2". Multiple instances can share a Type. Used for type-specific
	// behavior (mesh capability, AmneziaWG obfuscation fields, install).
	Type() string

	Status(ctx context.Context) (ServerStatus, error)
	ListPeers(ctx context.Context) ([]Peer, error)
	AddPeer(ctx context.Context, spec PeerSpec) (NewPeerResult, error)
	UpdatePeer(ctx context.Context, id string, spec PeerSpec) error
	RemovePeer(ctx context.Context, id string) error
	UpdateServerConfig(ctx context.Context, cfg ServerConfig) error
}

// ForwardingManager is implemented by providers that can manage host-side
// FORWARD rules for the cross-provider mesh. Not every provider supports it
// (OpenVPN/IKEv2 stubs don't), so callers type-assert.
type ForwardingManager interface {
	ForwardingEnabled(ctx context.Context) (bool, error)
	EnableForwarding(ctx context.Context) error
}

// KeyRotator is implemented by providers that can regenerate a peer's
// keypair in place (wg-family). Callers type-assert.
type KeyRotator interface {
	RotatePeerKey(ctx context.Context, oldPubKey string) (NewPeerResult, error)
}

// ConfiguredPeerAdder is implemented by providers that can add a peer with a
// pre-existing public key (no key generation) -- used to re-enable a
// previously disabled peer. Callers type-assert.
type ConfiguredPeerAdder interface {
	AddConfiguredPeer(ctx context.Context, publicKey string, spec PeerSpec) error
}

// ConfRestorer is implemented by providers whose whole config file can be
// replaced with a raw snapshot (wg-family). Callers type-assert.
type ConfRestorer interface {
	RestoreConf(ctx context.Context, content string) error
}

// NetworkController is implemented by providers whose host-side networking
// (forwarding, internet-egress NAT) the panel manages. Callers type-assert.
type NetworkController interface {
	EgressEnabled(ctx context.Context) (bool, error)
	ApplyNetworking(ctx context.Context, egress bool) error
}

// ServiceNamed is implemented by providers backed by a systemd unit, so the
// panel can start/stop/enable/disable the service to save resources.
type ServiceNamed interface {
	ServiceName() string
}

// ClientConfigProvider is implemented by certificate-based providers
// (OpenVPN, IKEv2) that manage their own client credential storage and
// produce a downloadable client config file themselves. When a provider
// implements this, the API layer does NOT seal a private key into
// peer_secrets for it (AddPeer persists what it needs), and downloads go
// through ClientConfigFile rather than the wg-family config builder.
type ClientConfigProvider interface {
	ClientConfigFile(ctx context.Context, id string) (filename string, data []byte, err error)
}

// ClientProfileProvider is implemented by cert-based providers that offer
// alternative single-file client profiles beyond the default ClientConfigFile
// (e.g. IKEv2 .mobileconfig for Apple, .sswan for the strongSwan Android app).
// Callers type-assert.
type ClientProfileProvider interface {
	// ProfileFormats lists the extra formats available (e.g. "mobileconfig",
	// "sswan"), excluding the default returned by ClientConfigFile.
	ProfileFormats() []string
	// ClientProfile builds a profile in the given format for a client.
	ClientProfile(ctx context.Context, id, format string) (filename string, data []byte, err error)
}

// CAImporter is implemented by cert-based providers that can adopt an
// externally-supplied CA (BYOC, e.g. a step-ca intermediate) instead of the
// panel's internally-generated one. Importing a new CA invalidates certs
// issued under the old one -- the server must be re-provisioned afterwards.
type CAImporter interface {
	ImportCA(ctx context.Context, certPEM, keyPEM string) error
}

// CSRSigner is implemented by cert-based providers that can enroll a client
// from a client-supplied Certificate Signing Request. The client keeps its
// private key (it never reaches the server); the panel signs the CSR and
// stores only the issued certificate. Callers type-assert.
type CSRSigner interface {
	AddPeerFromCSR(ctx context.Context, csrPEM string, spec PeerSpec) (NewPeerResult, error)
}

// ServerProvisioner is implemented by providers that need an explicit
// server bring-up (CA, certs, config, service) before clients can be added
// -- OpenVPN/IKEv2. pushRoutes are the networks advertised to all clients;
// redirectGateway requests internet egress.
type ServerProvisioner interface {
	EnsureServer(ctx context.Context, pushRoutes []string, redirectGateway bool) error
}

// Registry holds the provider instances known to the panel, keyed by instance
// name, preserving registration order for stable UI/iteration.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	order     []string
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[p.Name()]; !exists {
		r.order = append(r.order, p.Name())
	}
	r.providers[p.Name()] = p
}

// Unregister removes an instance by name (used when a server is removed or
// rebuilt). No-op if absent.
func (r *Registry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[name]; !ok {
		return
	}
	delete(r.providers, name)
	for i, n := range r.order {
		if n == name {
			r.order = append(r.order[:i], r.order[i+1:]...)
			break
		}
	}
}

func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	return p, ok
}

// List returns all instances in registration order.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.providers[name])
	}
	return out
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}
