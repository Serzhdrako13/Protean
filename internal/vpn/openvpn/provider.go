package openvpn

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"protean/internal/vpn"
	"protean/internal/vpn/pki"
)

// SSH is the remote-exec surface the provider needs (satisfied by
// *sshexec.Client).
type SSH interface {
	Run(ctx context.Context, cmd string) (string, error)
	ReadFile(ctx context.Context, path string) (string, error)
	WriteFile(ctx context.Context, path, content string) error
}

// Sealer encrypts/decrypts secret material at rest (satisfied by
// *auth.Encryptor).
type Sealer interface {
	Seal(plaintext string) ([]byte, error)
	Open(blob []byte) (string, error)
}

// Store is the persistence the provider needs (satisfied by *store.Store).
type Store interface {
	GetCAMaterial(ctx context.Context, provider string) (certPEM string, encKeyPEM []byte, source string, err error)
	SaveCAMaterial(ctx context.Context, provider, certPEM string, encKeyPEM []byte, source string) error
	SaveOpenVPNClient(ctx context.Context, provider, cn, certPEM string, encKeyPEM []byte, address, subnets string) error
	GetOpenVPNClient(ctx context.Context, provider, cn string) (certPEM string, encKeyPEM []byte, address, subnets string, err error)
	ListOpenVPNClients(ctx context.Context, provider string) (cns []string, addrs []string, subnets []string, err error)
	DeleteOpenVPNClient(ctx context.Context, provider, cn string) error
	AddRevokedCert(ctx context.Context, provider, serial, cn string) error
	ListRevokedCerts(ctx context.Context, provider string) ([]RevokedCert, error)
	NextCRLNumber(ctx context.Context, provider string) (int64, error)
}

// RevokedCert is a recorded revocation (serial as decimal string).
type RevokedCert struct {
	Serial    string
	RevokedAt time.Time
}

type Options struct {
	// Instance is the unique registry/DB key for this provider instance,
	// e.g. "openvpn" (single-server) or "hq/openvpn" (multi-server). Used as
	// the scope key for CA material, clients, CRL and routes. Defaults to
	// "openvpn".
	Instance    string
	Interface   string // instance name, e.g. "server" -> openvpn-server@server
	ConfPath    string // /etc/openvpn/server/<iface>.conf
	ServerDir   string // /etc/openvpn/server
	CCDDir      string // /etc/openvpn/server/ccd
	StatusPath  string // /run/openvpn-server/status-<iface>.log
	ServiceName string // openvpn-server@<iface>
	PublicHost  string
	ListenPort  int
	Proto       string
	ServerNet   string // 10.8.0.0
	ServerMask  string // 255.255.255.0
	// MTU/Mssfix: 0 = leave unset. See ServerParams.TunMTU/Mssfix (the same
	// distinction) -- an admin sets these when tunnel packets get silently
	// fragmented/black-holed on mobile/PPPoE/nested-tunnel networks.
	MTU    int
	Mssfix int

	SSH   SSH
	Store Store
	Enc   Sealer
}

type Provider struct {
	opts Options
	mu   sync.Mutex
	ca   *pki.CA // cached after first load
}

func New(opts Options) *Provider {
	if opts.Proto == "" {
		opts.Proto = "udp"
	}
	if opts.Instance == "" {
		opts.Instance = "openvpn"
	}
	return &Provider{opts: opts}
}

func (p *Provider) Name() string { return p.opts.Instance }
func (p *Provider) Type() string { return "openvpn" }

func (p *Provider) ServiceName() string { return p.opts.ServiceName }

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	leafValidity   = 2 * 365 * 24 * time.Hour
	serverCertName = "server"
)

// getCA loads the persisted CA, generating and storing an internal one on
// first use.
func (p *Provider) getCA(ctx context.Context) (*pki.CA, error) {
	if p.ca != nil {
		return p.ca, nil
	}
	certPEM, encKey, _, err := p.opts.Store.GetCAMaterial(ctx, p.opts.Instance)
	if err == nil {
		keyPEM, derr := p.opts.Enc.Open(encKey)
		if derr != nil {
			return nil, fmt.Errorf("decrypt CA key: %w", derr)
		}
		ca, lerr := pki.LoadCA(certPEM, keyPEM)
		if lerr != nil {
			return nil, lerr
		}
		p.ca = ca
		return ca, nil
	}

	// None stored yet -> generate an internal CA and persist it.
	ca, err := pki.NewInternalCA(caValidity)
	if err != nil {
		return nil, err
	}
	enc, err := p.opts.Enc.Seal(ca.CAKeyPEM())
	if err != nil {
		return nil, err
	}
	if err := p.opts.Store.SaveCAMaterial(ctx, p.opts.Instance, ca.CACertPEM(), enc, "internal"); err != nil {
		return nil, err
	}
	p.ca = ca
	return ca, nil
}

// ImportCA adopts an externally-supplied CA (cert + key). Certs issued under
// the previous CA stop validating; re-provision the server afterwards.
func (p *Provider) ImportCA(ctx context.Context, certPEM, keyPEM string) error {
	ca, err := pki.LoadCA(certPEM, keyPEM)
	if err != nil {
		return err
	}
	enc, err := p.opts.Enc.Seal(keyPEM)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.opts.Store.SaveCAMaterial(ctx, p.opts.Instance, certPEM, enc, "external"); err != nil {
		return err
	}
	p.ca = ca
	return nil
}

// RebuildCRL regenerates the CRL from all recorded revocations (including any
// just imported via ImportCA's crl_pem) and pushes it to the host, without
// waiting for a full re-provision.
func (p *Provider) RebuildCRL(ctx context.Context) error {
	ca, err := p.getCA(ctx)
	if err != nil {
		return err
	}
	return p.rebuildCRL(ctx, ca)
}

func (p *Provider) Status(ctx context.Context) (vpn.ServerStatus, error) {
	status := vpn.ServerStatus{Provider: p.opts.Instance}
	active, err := p.serviceActive(ctx)
	if err != nil {
		return status, err
	}
	status.Up = active
	if !active {
		return status, nil
	}
	status.ListenPort = p.opts.ListenPort
	status.MTU = p.opts.MTU
	status.Mssfix = p.opts.Mssfix
	if p.opts.ServerNet != "" && p.opts.ServerMask != "" {
		if ones, _ := net.IPMask(net.ParseIP(p.opts.ServerMask).To4()).Size(); ones > 0 {
			status.Address = fmt.Sprintf("%s/%d", firstHost(p.opts.ServerNet), ones)
		}
	}
	if p.opts.PublicHost != "" {
		status.Endpoint = fmt.Sprintf("%s:%d", p.opts.PublicHost, p.opts.ListenPort)
	}

	clients, _ := p.connected(ctx)
	status.PeerCount = len(clients)
	for _, c := range clients {
		status.TotalRxBytes += c.BytesReceived
		status.TotalTxBytes += c.BytesSent
		status.PeersOnline++
	}
	return status, nil
}

func (p *Provider) serviceActive(ctx context.Context) (bool, error) {
	// "show -p ActiveState --value", not "is-active": ServiceName can
	// itself be a manually-created alias (e.g. openSUSE's openvpn package
	// ships openvpn@.service, not openvpn-server@.service -- see
	// ensure_openvpn_alias in protean-installer.sh), and is-active on an
	// aliased unit name has been confirmed live to misreport "inactive" on
	// systemd 232 (Astra Linux CE 2.12) after any daemon-reload, even while
	// the real unit is genuinely running. show's ActiveState always
	// resolves correctly and always exits 0, so no error path to handle.
	out, _ := p.opts.SSH.Run(ctx, "systemctl show "+shellQuote(p.opts.ServiceName)+" -p ActiveState --value")
	return strings.TrimSpace(out) == "active", nil
}

func (p *Provider) connected(ctx context.Context) ([]ConnectedClient, error) {
	if p.opts.StatusPath == "" {
		return nil, nil
	}
	raw, err := p.opts.SSH.ReadFile(ctx, p.opts.StatusPath)
	if err != nil {
		return nil, nil // status file may not exist yet
	}
	return ParseStatus(raw), nil
}

// ListPeers merges connected clients (from the status file) with configured
// clients (from the DB), so offline clients still show.
func (p *Provider) ListPeers(ctx context.Context) ([]vpn.Peer, error) {
	online := map[string]ConnectedClient{}
	if cs, err := p.connected(ctx); err == nil {
		for _, c := range cs {
			online[c.CommonName] = c
		}
	}

	cns, addrs, subnets, err := p.opts.Store.ListOpenVPNClients(ctx, p.opts.Instance)
	if err != nil {
		return nil, err
	}
	peers := make([]vpn.Peer, 0, len(cns))
	for i, cn := range cns {
		allowed := []string{}
		if addrs[i] != "" {
			allowed = append(allowed, addrs[i])
		}
		if subnets[i] != "" {
			allowed = append(allowed, strings.Split(subnets[i], ",")...)
		}
		peer := vpn.Peer{
			ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: allowed,
		}
		if c, ok := online[cn]; ok {
			peer.Online = true
			peer.Endpoint = c.RealAddress
			peer.RxBytes = c.BytesReceived
			peer.TxBytes = c.BytesSent
			peer.LastHandshake = c.ConnectedSince
			// A client with no ccd static address (the common case -- most
			// clients just get whatever the server pool hands out) still
			// gets a real tunnel address the moment it connects; the status
			// file's VirtualAddress column already carries it (parsed above)
			// but was never surfaced here, so every dynamically-addressed
			// client showed no address at all despite being online.
			if len(allowed) == 0 && c.VirtualAddress != "" {
				peer.AllowedIPs = []string{c.VirtualAddress}
			}
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

// AddPeer issues a client certificate, stores it, and writes a
// client-config-dir entry for its tunnel address and any site subnets
// (iroute). No server restart is needed -- the client just needs its cert,
// and the CA is already trusted.
func (p *Provider) AddPeer(ctx context.Context, spec vpn.PeerSpec) (vpn.NewPeerResult, error) {
	cn := strings.TrimSpace(spec.Name)
	if cn == "" {
		return vpn.NewPeerResult{}, fmt.Errorf("name (CN) must not be empty")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	ca, err := p.getCA(ctx)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	creds, err := ca.IssueClient(cn, leafValidity)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	enc, err := p.opts.Enc.Seal(creds.KeyPEM)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}

	// spec.AllowedIPs: first /32 is the client's tunnel address, the rest are
	// site subnets it serves (iroute).
	address, subnets := splitClientAllowedIPs(spec.AllowedIPs)
	if err := p.writeCCD(ctx, cn, address, subnets); err != nil {
		return vpn.NewPeerResult{}, err
	}
	if err := p.opts.Store.SaveOpenVPNClient(ctx, p.opts.Instance, cn, creds.CertPEM, enc, address, strings.Join(subnets, ",")); err != nil {
		return vpn.NewPeerResult{}, err
	}

	return vpn.NewPeerResult{Peer: vpn.Peer{
		ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: spec.AllowedIPs,
	}}, nil
}

// AddPeerFromCSR enrolls a client from a client-supplied CSR: the panel signs
// it (the client keeps its private key) and stores only the certificate. The
// downloadable .ovpn therefore omits the <key> block -- the client supplies
// its own key file.
func (p *Provider) AddPeerFromCSR(ctx context.Context, csrPEM string, spec vpn.PeerSpec) (vpn.NewPeerResult, error) {
	cn := strings.TrimSpace(spec.Name)
	if cn == "" {
		return vpn.NewPeerResult{}, fmt.Errorf("name (CN) must not be empty")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	ca, err := p.getCA(ctx)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	certPEM, err := ca.SignCSRWithCN(csrPEM, cn, leafValidity)
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	address, subnets := splitClientAllowedIPs(spec.AllowedIPs)
	if err := p.writeCCD(ctx, cn, address, subnets); err != nil {
		return vpn.NewPeerResult{}, err
	}
	// nil encrypted key => CSR-based client; no server-held private key.
	if err := p.opts.Store.SaveOpenVPNClient(ctx, p.opts.Instance, cn, certPEM, nil, address, strings.Join(subnets, ",")); err != nil {
		return vpn.NewPeerResult{}, err
	}
	return vpn.NewPeerResult{Peer: vpn.Peer{
		ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: spec.AllowedIPs,
	}}, nil
}

// ImportPeer adopts an already-issued client certificate (e.g. from a VPN
// server being taken over by the panel) instead of issuing a new one. The
// cert must verify against the current CA -- a cert from a DIFFERENT CA
// (the panel's own internal one, or a CA not yet imported) is rejected, so
// this only works after ImportCA has adopted the matching CA. keyPEM is
// optional: pasting it enables config/QR downloads later, matching the
// CSR-enrolled-peer trade-off already explained elsewhere in the UI; without
// it the client keeps using its own existing config file.
func (p *Provider) ImportPeer(ctx context.Context, certPEM, keyPEM string) (vpn.Peer, error) {
	certPEM = strings.TrimSpace(certPEM)
	keyPEM = strings.TrimSpace(keyPEM)
	p.mu.Lock()
	defer p.mu.Unlock()

	ca, err := p.getCA(ctx)
	if err != nil {
		return vpn.Peer{}, err
	}
	cn, err := ca.VerifyClientCert(certPEM)
	if err != nil {
		return vpn.Peer{}, err
	}
	var enc []byte
	if keyPEM != "" {
		if err := pki.MatchesPrivateKey(certPEM, keyPEM); err != nil {
			return vpn.Peer{}, err
		}
		enc, err = p.opts.Enc.Seal(keyPEM)
		if err != nil {
			return vpn.Peer{}, err
		}
	}
	if err := p.writeCCD(ctx, cn, "", nil); err != nil {
		return vpn.Peer{}, err
	}
	if err := p.opts.Store.SaveOpenVPNClient(ctx, p.opts.Instance, cn, certPEM, enc, "", ""); err != nil {
		return vpn.Peer{}, err
	}
	return vpn.Peer{ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn}, nil
}

func (p *Provider) UpdatePeer(ctx context.Context, id string, spec vpn.PeerSpec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	certPEM, encKey, _, _, err := p.opts.Store.GetOpenVPNClient(ctx, p.opts.Instance, id)
	if err != nil {
		return err
	}
	address, subnets := splitClientAllowedIPs(spec.AllowedIPs)
	if err := p.writeCCD(ctx, id, address, subnets); err != nil {
		return err
	}
	return p.opts.Store.SaveOpenVPNClient(ctx, p.opts.Instance, id, certPEM, encKey, address, strings.Join(subnets, ","))
}

func (p *Provider) RemovePeer(ctx context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Revoke the client's certificate (add to CRL) before dropping it, so a
	// removed client cannot reconnect until its cert would otherwise expire.
	if err := p.revoke(ctx, id); err != nil {
		return err
	}
	// Best-effort remove the ccd entry; then drop the stored client.
	_, _ = p.opts.SSH.Run(ctx, "rm -f "+shellQuote(p.ccdPath(id)))
	return p.opts.Store.DeleteOpenVPNClient(ctx, p.opts.Instance, id)
}

// revoke records the client cert's serial as revoked and rewrites the CRL file
// on the host. OpenVPN re-reads the crl-verify file on each new connection, so
// no service restart is needed.
func (p *Provider) revoke(ctx context.Context, cn string) error {
	certPEM, _, _, _, err := p.opts.Store.GetOpenVPNClient(ctx, p.opts.Instance, cn)
	if err != nil {
		return nil // nothing stored -> nothing to revoke
	}
	serial, err := pki.SerialFromCertPEM(certPEM)
	if err != nil {
		return fmt.Errorf("parse serial: %w", err)
	}
	if err := p.opts.Store.AddRevokedCert(ctx, p.opts.Instance, serial.String(), cn); err != nil {
		return fmt.Errorf("record revocation: %w", err)
	}
	ca, err := p.getCA(ctx)
	if err != nil {
		return err
	}
	return p.rebuildCRL(ctx, ca)
}

// rebuildCRL regenerates the CRL from all recorded revocations and writes it to
// the host. An empty revocation set still yields a valid (empty) CRL.
func (p *Provider) rebuildCRL(ctx context.Context, ca *pki.CA) error {
	rows, err := p.opts.Store.ListRevokedCerts(ctx, p.opts.Instance)
	if err != nil {
		return err
	}
	revoked := make([]pki.RevokedCert, 0, len(rows))
	for _, r := range rows {
		serial, ok := new(big.Int).SetString(r.Serial, 10)
		if !ok {
			continue
		}
		revoked = append(revoked, pki.RevokedCert{Serial: serial, RevokedAt: r.RevokedAt})
	}
	num, err := p.opts.Store.NextCRLNumber(ctx, p.opts.Instance)
	if err != nil {
		return err
	}
	now := time.Now()
	// Long NextUpdate: the file is rewritten on every revocation, so freshness
	// is handled operationally rather than by a short expiry window (an expired
	// CRL would make OpenVPN reject all clients).
	crlPEM, err := ca.CreateCRL(revoked, num, now.Add(-time.Hour), now.Add(caValidity))
	if err != nil {
		return err
	}
	return p.opts.SSH.WriteFile(ctx, p.crlPath(), crlPEM)
}

// ClientConfigFile builds the .ovpn bundle for a stored client.
func (p *Provider) ClientConfigFile(ctx context.Context, id string) (string, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ca, err := p.getCA(ctx)
	if err != nil {
		return "", nil, err
	}
	certPEM, encKey, _, _, err := p.opts.Store.GetOpenVPNClient(ctx, p.opts.Instance, id)
	if err != nil {
		return "", nil, err
	}
	// CSR-based clients have no server-held key (encKey nil): the .ovpn omits
	// <key> and the client supplies its own.
	var keyPEM string
	if len(encKey) > 0 {
		keyPEM, err = p.opts.Enc.Open(encKey)
		if err != nil {
			return "", nil, err
		}
	}
	tlsCrypt, _ := p.opts.SSH.ReadFile(ctx, p.tlsCryptPath())

	bundle := BundleParams{
		RemoteHost:    p.opts.PublicHost,
		RemotePort:    p.opts.ListenPort,
		Proto:         p.opts.Proto,
		TunMTU:        p.opts.MTU,
		Mssfix:        p.opts.Mssfix,
		CACertPEM:     ca.CACertPEM(),
		ClientCertPEM: certPEM,
		ClientKeyPEM:  keyPEM,
		TLSCryptPEM:   tlsCrypt,
	}.Build()
	return sanitizeName(id) + ".ovpn", []byte(bundle), nil
}

func (p *Provider) UpdateServerConfig(ctx context.Context, cfg vpn.ServerConfig) error {
	// Server bring-up/reconfigure is handled by EnsureServer; a plain
	// listen-port/address edit maps onto it. MTU/mssfix go through a
	// different path (internal/api/api_network.go's OpenVPN branch: persist
	// into server_instances.Config, rebuild the provider, re-provision) since
	// they live in Options, set at provider-construction time, not something
	// this method can hot-swap on the receiver.
	return fmt.Errorf("use the OpenVPN setup flow to (re)configure the server")
}

// EnsureServer provisions (or re-provisions) the OpenVPN server: CA, server
// cert/key, tls-crypt key and config file are written to the host, the ccd
// directory is created, and the service is enabled and (re)started. Idempotent
// -- existing CA/tls-crypt are reused.
// detectsLegacyOpenVPN reports whether the installed openvpn binary
// predates 2.5, when "data-ciphers"/"data-ciphers-fallback" were
// introduced -- confirmed live that OpenVPN 2.4.x rejects those directives
// outright ("Unrecognized option ... data-ciphers") and refuses to start
// at all. Not distro-specific: any still-deployed 2.4.x host would hit
// this (confirmed live on Astra Linux CE 2.12, whose own repo only
// carries 2.4.7, but the same version could show up on an old
// Debian/Ubuntu LTS too). Defaults to false (modern syntax) if detection
// fails for any reason -- correct for every distro this panel actually
// targets; only a genuinely old install needs the fallback.
func detectsLegacyOpenVPN(ctx context.Context, ssh SSH) bool {
	// Absolute path, not "openvpn" bare: a plain (non-sudo) SSH exec
	// session's PATH doesn't include /usr/sbin (confirmed live:
	// "/usr/local/bin:/usr/bin:/bin:/usr/games"), where the binary
	// actually lives on every distro this panel targets -- same class of
	// PATH gap as the earlier ip_forward/sysctl fix elsewhere in this
	// codebase. "; true" forces the shell's own exit code to 0: OpenVPN's
	// own "--version" genuinely exits 1 even on success (confirmed live,
	// 2.4.7), and sshexec.Client.Run discards stdout entirely whenever the
	// remote command's exit code is non-zero -- without this the version
	// banner is unrecoverable, not just harder to parse.
	out, err := ssh.Run(ctx, "/usr/sbin/openvpn --version; true")
	if err != nil {
		return false
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f != "OpenVPN" || i+1 >= len(fields) {
			continue
		}
		parts := strings.SplitN(fields[i+1], ".", 3)
		if len(parts) < 2 {
			return false
		}
		major, errMajor := strconv.Atoi(parts[0])
		minor, errMinor := strconv.Atoi(parts[1])
		if errMajor != nil || errMinor != nil {
			return false
		}
		return major < 2 || (major == 2 && minor < 5)
	}
	return false
}

func (p *Provider) EnsureServer(ctx context.Context, pushRoutes []string, redirectGateway bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ca, err := p.getCA(ctx)
	if err != nil {
		return err
	}

	// Server certificate (issued fresh each ensure; cheap and avoids drift).
	var sans []string
	if p.opts.PublicHost != "" {
		sans = append(sans, p.opts.PublicHost)
	}
	certPEM, keyPEM, err := ca.IssueServer(serverCertName, sans, nil, leafValidity)
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}

	// tls-crypt key: reuse if present, else generate.
	tlsCrypt, err := p.opts.SSH.ReadFile(ctx, p.tlsCryptPath())
	if err != nil || !strings.Contains(tlsCrypt, "OpenVPN Static key") {
		tlsCrypt, err = GenTLSCrypt()
		if err != nil {
			return err
		}
	}

	// (Re)build the CRL so crl-verify always points at a valid file, even
	// before any revocation (an empty CRL is valid).
	if err := p.rebuildCRL(ctx, ca); err != nil {
		return fmt.Errorf("build CRL: %w", err)
	}

	files := map[string]string{
		p.opts.ServerDir + "/ca.crt":     ca.CACertPEM(),
		p.opts.ServerDir + "/server.crt": certPEM,
		p.opts.ServerDir + "/server.key": keyPEM,
		p.tlsCryptPath():                 tlsCrypt,
	}
	// The ccd dir is created without sudo -- setup-host.sh pre-creates
	// /etc/openvpn/server group-writable by the panel, so plain mkdir works
	// and files below can be written without sudo (same model as wg confs).
	if _, err := p.opts.SSH.Run(ctx, "mkdir -p "+shellQuote(p.opts.CCDDir)); err != nil {
		return fmt.Errorf("mkdir ccd: %w", err)
	}
	for path, content := range files {
		if err := p.opts.SSH.WriteFile(ctx, path, content); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	conf := ServerParams{
		Port: p.opts.ListenPort, Proto: p.opts.Proto,
		ServerNet: p.opts.ServerNet, ServerMask: p.opts.ServerMask,
		TunMTU: p.opts.MTU, Mssfix: p.opts.Mssfix,
		CACertPath: p.opts.ServerDir + "/ca.crt", ServerCert: p.opts.ServerDir + "/server.crt",
		ServerKey: p.opts.ServerDir + "/server.key", TLSCryptKey: p.tlsCryptPath(),
		ClientConfigDir: p.opts.CCDDir, StatusPath: p.opts.StatusPath,
		CRLPath:    p.crlPath(),
		PushRoutes: pushRoutes, RedirectGateway: redirectGateway,
		LegacyCipher: detectsLegacyOpenVPN(ctx, p.opts.SSH),
	}
	if err := p.opts.SSH.WriteFile(ctx, p.opts.ConfPath, conf.Render()); err != nil {
		return fmt.Errorf("write server conf: %w", err)
	}

	installer := vpn.NewInstaller(p.opts.SSH)
	if _, err := installer.Service(ctx, "enable", p.opts.ServiceName); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}
	if _, err := installer.Service(ctx, "restart", p.opts.ServiceName); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}
	return nil
}

// --- helpers ---

func (p *Provider) ccdPath(cn string) string { return p.opts.CCDDir + "/" + cn }
func (p *Provider) tlsCryptPath() string     { return p.opts.ServerDir + "/tls-crypt.key" }
func (p *Provider) crlPath() string          { return p.opts.ServerDir + "/crl.pem" }

func (p *Provider) writeCCD(ctx context.Context, cn, address string, subnets []string) error {
	var b strings.Builder
	if address != "" {
		if ip, _, err := net.ParseCIDR(address); err == nil {
			// ifconfig-push needs an IP + netmask; use the server mask.
			b.WriteString(fmt.Sprintf("ifconfig-push %s %s\n", ip.String(), p.opts.ServerMask))
		}
	}
	for _, s := range subnets {
		if net, mask, ok := cidrToNetMask(s); ok {
			b.WriteString(fmt.Sprintf("iroute %s %s\n", net, mask))
		}
	}
	if b.Len() == 0 {
		b.WriteString("# no per-client options\n")
	}
	return p.opts.SSH.WriteFile(ctx, p.ccdPath(cn), b.String())
}

func splitClientAllowedIPs(allowed []string) (address string, subnets []string) {
	for _, a := range allowed {
		if _, ipnet, err := net.ParseCIDR(a); err == nil {
			ones, bits := ipnet.Mask.Size()
			if ones == bits {
				if address == "" {
					address = a
				}
				continue
			}
			subnets = append(subnets, a)
		}
	}
	return address, subnets
}

func firstHost(network string) string {
	ip := net.ParseIP(network).To4()
	if ip == nil {
		return network
	}
	ip[3]++ // .0 network -> .1 server address (topology subnet convention)
	return ip.String()
}

func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "client"
	}
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
