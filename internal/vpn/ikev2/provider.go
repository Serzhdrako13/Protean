package ikev2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"protean/internal/vpn"
	"protean/internal/vpn/pki"
)

type SSH interface {
	Run(ctx context.Context, cmd string) (string, error)
	ReadFile(ctx context.Context, path string) (string, error)
	WriteFile(ctx context.Context, path, content string) error
}

type Sealer interface {
	Seal(plaintext string) ([]byte, error)
	Open(blob []byte) (string, error)
}

type Store interface {
	GetCAMaterial(ctx context.Context, provider string) (certPEM string, encKeyPEM []byte, source string, err error)
	SaveCAMaterial(ctx context.Context, provider, certPEM string, encKeyPEM []byte, source string) error
	SaveClient(ctx context.Context, provider, cn, certPEM string, encKeyPEM []byte, p12pass, address, subnets string) error
	GetClient(ctx context.Context, provider, cn string) (certPEM string, encKeyPEM []byte, p12pass, address, subnets string, err error)
	ListClients(ctx context.Context, provider string) (cns, addrs, subnets, p12pass []string, err error)
	DeleteClient(ctx context.Context, provider, cn string) error
	AddRevokedCert(ctx context.Context, provider, serial, cn string) error
	ListRevokedCerts(ctx context.Context, provider string) ([]RevokedCert, error)
	NextCRLNumber(ctx context.Context, provider string) (int64, error)
	SaveServerRoutes(ctx context.Context, provider string, pushRoutes []string, egress bool) error
	GetServerRoutes(ctx context.Context, provider string) (pushRoutes []string, egress bool, ok bool, err error)
}

// RevokedCert is a recorded revocation (serial as decimal string).
type RevokedCert struct {
	Serial    string
	RevokedAt time.Time
}

type Options struct {
	// Instance is the unique registry/DB key, e.g. "ikev2" or "hq/ikev2".
	// Scopes CA material, clients, CRL and routes. Defaults to "ikev2".
	Instance    string
	ConnName    string
	SwanctlDir  string // /etc/swanctl
	ServiceName string // "ipsec" -- the portable strongSwan service alias, not "strongswan"/"strongswan-starter" directly
	ServerID    string // public host (cert SAN)
	Pool        string // 10.9.0.0/24
	DNS         []string
	SSH         SSH
	Store       Store
	Enc         Sealer
}

type Provider struct {
	opts Options
	mu   sync.Mutex
	ca   *pki.CA
}

func New(opts Options) *Provider {
	if opts.ConnName == "" {
		opts.ConnName = "protean"
	}
	if opts.Instance == "" {
		opts.Instance = "ikev2"
	}
	return &Provider{opts: opts}
}

func (p *Provider) Name() string        { return p.opts.Instance }
func (p *Provider) Type() string        { return "ikev2" }
func (p *Provider) ServiceName() string { return p.opts.ServiceName }

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	leafValidity = 2 * 365 * 24 * time.Hour
)

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
	st := vpn.ServerStatus{Provider: p.opts.Instance}
	// "show -p ActiveState --value", not "is-active": confirmed live that
	// is-active on an aliased unit name (ipsec -> strongswan) can misreport
	// "inactive" on systemd 232 (Astra Linux CE 2.12) after any
	// daemon-reload, even while the real unit is genuinely running and
	// show's own ActiveState resolves correctly regardless. show also
	// always exits 0, avoiding SSH.Run's stdout-discard-on-nonzero-exit
	// behavior that made "out" unreliable here before.
	out, _ := p.opts.SSH.Run(ctx, "systemctl show "+shellQuote(p.opts.ServiceName)+" -p ActiveState --value")
	st.Up = strings.TrimSpace(out) == "active"
	if !st.Up {
		return st, nil
	}
	if p.opts.ServerID != "" {
		st.Endpoint = p.opts.ServerID + ":500"
	}
	st.Address = p.opts.Pool
	sas := p.activeSAs(ctx)
	st.PeersOnline = len(sas)
	st.PeerCount = len(sas)
	return st, nil
}

func (p *Provider) activeSAs(ctx context.Context) []ActiveSA {
	out, err := p.opts.SSH.Run(ctx, "sudo swanctl --list-sas")
	if err != nil {
		return nil
	}
	return ParseListSAs(out)
}

func (p *Provider) ListPeers(ctx context.Context) ([]vpn.Peer, error) {
	online := map[string]ActiveSA{}
	for _, sa := range p.activeSAs(ctx) {
		online[sa.RemoteID] = sa
	}
	cns, addrs, subnets, p12pass, err := p.opts.Store.ListClients(ctx, p.opts.Instance)
	if err != nil {
		return nil, err
	}
	peers := make([]vpn.Peer, 0, len(cns))
	for i, cn := range cns {
		var allowed []string
		if addrs[i] != "" {
			allowed = append(allowed, addrs[i])
		}
		if subnets[i] != "" {
			allowed = append(allowed, strings.Split(subnets[i], ",")...)
		}
		peer := vpn.Peer{
			ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: allowed,
			Extra: map[string]string{"p12password": p12pass[i]},
		}
		if sa, ok := online[cn]; ok {
			peer.Online = true
			peer.Endpoint = sa.Remote
			// A client with no static allowed-IP configured (the normal
			// case -- these are road-warriors, addressed from the pool)
			// still gets a real tunnel address the moment its CHILD_SA
			// comes up; sa.VIP already carries it (see ParseListSAs) but
			// was never surfaced here, so an online ikev2 client showed no
			// address at all.
			if len(allowed) == 0 && sa.VIP != "" {
				peer.AllowedIPs = []string{sa.VIP}
			}
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

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
	pass, err := randPassword()
	if err != nil {
		return vpn.NewPeerResult{}, err
	}
	address, subnets := splitAllowedIPs(spec.AllowedIPs)
	if err := p.opts.Store.SaveClient(ctx, p.opts.Instance, cn, creds.CertPEM, enc, pass, address, strings.Join(subnets, ",")); err != nil {
		return vpn.NewPeerResult{}, err
	}
	if err := p.applyClients(ctx); err != nil {
		return vpn.NewPeerResult{}, err
	}
	return vpn.NewPeerResult{Peer: vpn.Peer{ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: spec.AllowedIPs}}, nil
}

// AddPeerFromCSR enrolls a client from a client-supplied CSR: the panel signs
// it (the client keeps its private key) and stores only the certificate. No
// .p12 can be built (that needs the key); ClientConfigFile returns the signed
// certificate + CA chain instead, which the client imports alongside its key.
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
	address, subnets := splitAllowedIPs(spec.AllowedIPs)
	// nil key + empty p12 password => CSR-based client.
	if err := p.opts.Store.SaveClient(ctx, p.opts.Instance, cn, certPEM, nil, "", address, strings.Join(subnets, ",")); err != nil {
		return vpn.NewPeerResult{}, err
	}
	if err := p.applyClients(ctx); err != nil {
		return vpn.NewPeerResult{}, err
	}
	return vpn.NewPeerResult{Peer: vpn.Peer{ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn, AllowedIPs: spec.AllowedIPs}}, nil
}

// ImportPeer adopts an already-issued client certificate (e.g. from a
// strongSwan/swanctl server being taken over by the panel) instead of
// issuing a new one. The cert must verify against the current CA -- only
// works after ImportCA has adopted the matching CA. keyPEM is optional: with
// it, a .p12 can be built later (a fresh random password is generated for
// it, same as AddPeer); without it the client keeps its existing config.
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
	var pass string
	if keyPEM != "" {
		if err := pki.MatchesPrivateKey(certPEM, keyPEM); err != nil {
			return vpn.Peer{}, err
		}
		enc, err = p.opts.Enc.Seal(keyPEM)
		if err != nil {
			return vpn.Peer{}, err
		}
		pass, err = randPassword()
		if err != nil {
			return vpn.Peer{}, err
		}
	}
	if err := p.opts.Store.SaveClient(ctx, p.opts.Instance, cn, certPEM, enc, pass, "", ""); err != nil {
		return vpn.Peer{}, err
	}
	if err := p.applyClients(ctx); err != nil {
		return vpn.Peer{}, err
	}
	return vpn.Peer{ID: cn, Provider: p.opts.Instance, Name: cn, PublicKey: cn}, nil
}

func (p *Provider) UpdatePeer(ctx context.Context, id string, spec vpn.PeerSpec) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cert, encKey, pass, _, _, err := p.opts.Store.GetClient(ctx, p.opts.Instance, id)
	if err != nil {
		return err
	}
	address, subnets := splitAllowedIPs(spec.AllowedIPs)
	if err := p.opts.Store.SaveClient(ctx, p.opts.Instance, id, cert, encKey, pass, address, strings.Join(subnets, ",")); err != nil {
		return err
	}
	// Regenerate connections so a changed site subnet takes effect.
	return p.applyClients(ctx)
}

func (p *Provider) RemovePeer(ctx context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	// Revoke the client's cert (add to CRL + reload) before dropping it.
	if err := p.revoke(ctx, id); err != nil {
		return err
	}
	if err := p.opts.Store.DeleteClient(ctx, p.opts.Instance, id); err != nil {
		return err
	}
	// Regenerate connections so the removed site client's block disappears.
	return p.applyClients(ctx)
}

func (p *Provider) crlPath() string { return p.opts.SwanctlDir + "/x509crl/crl.pem" }

// revoke records the client cert's serial, rewrites the CRL and reloads
// strongSwan credentials so the revocation takes effect.
func (p *Provider) revoke(ctx context.Context, cn string) error {
	certPEM, _, _, _, _, err := p.opts.Store.GetClient(ctx, p.opts.Instance, cn)
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
	if err := p.rebuildCRL(ctx, ca); err != nil {
		return err
	}
	// Reload creds so strongSwan picks up the updated CRL.
	_, _ = p.opts.SSH.Run(ctx, "sudo swanctl --load-all")
	return nil
}

// rebuildCRL regenerates the CRL from all recorded revocations and writes it to
// the swanctl x509crl directory.
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
	crlPEM, err := ca.CreateCRL(revoked, num, now.Add(-time.Hour), now.Add(caValidity))
	if err != nil {
		return err
	}
	return p.opts.SSH.WriteFile(ctx, p.crlPath(), crlPEM)
}

func (p *Provider) UpdateServerConfig(ctx context.Context, cfg vpn.ServerConfig) error {
	return fmt.Errorf("use the IKEv2 setup flow to (re)configure the server")
}

// ClientConfigFile returns a PKCS#12 (.p12) bundle for the client. The import
// password is stored and shown in the UI.
func (p *Provider) ClientConfigFile(ctx context.Context, id string) (string, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ca, err := p.getCA(ctx)
	if err != nil {
		return "", nil, err
	}
	cert, encKey, pass, _, _, err := p.opts.Store.GetClient(ctx, p.opts.Instance, id)
	if err != nil {
		return "", nil, err
	}
	// CSR-based client: no server-held key, so no .p12 is possible. Hand back
	// the signed certificate + CA chain; the client pairs it with its own key.
	if len(encKey) == 0 {
		bundle := strings.TrimRight(cert, "\n") + "\n" + strings.TrimRight(ca.CACertPEM(), "\n") + "\n"
		return sanitizeName(id) + "-cert.pem", []byte(bundle), nil
	}
	keyPEM, err := p.opts.Enc.Open(encKey)
	if err != nil {
		return "", nil, err
	}
	blob, err := BuildP12(cert, keyPEM, ca.CACertPEM(), pass)
	if err != nil {
		return "", nil, err
	}
	return sanitizeName(id) + ".p12", blob, nil
}

// ProfileFormats lists the extra single-file profile formats available beyond
// the default .p12 from ClientConfigFile.
func (p *Provider) ProfileFormats() []string { return []string{"mobileconfig", "sswan"} }

// ClientProfile builds an alternative single-file client profile: an Apple
// .mobileconfig or a strongSwan Android .sswan. Both embed the client PKCS#12,
// so a CSR-based client (no server-held key) cannot use them.
func (p *Provider) ClientProfile(ctx context.Context, id, format string) (string, []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ca, err := p.getCA(ctx)
	if err != nil {
		return "", nil, err
	}
	cert, encKey, pass, _, _, err := p.opts.Store.GetClient(ctx, p.opts.Instance, id)
	if err != nil {
		return "", nil, err
	}
	if len(encKey) == 0 {
		return "", nil, fmt.Errorf("%s profile needs the client private key; this client was enrolled from a CSR", format)
	}
	keyPEM, err := p.opts.Enc.Open(encKey)
	if err != nil {
		return "", nil, err
	}
	p12, err := BuildP12(cert, keyPEM, ca.CACertPEM(), pass)
	if err != nil {
		return "", nil, err
	}
	base := sanitizeName(id)
	switch format {
	case "mobileconfig":
		data := mobileConfigParams{CN: id, ServerID: p.opts.ServerID, P12: p12, P12Pass: pass}.build()
		return base + ".mobileconfig", data, nil
	case "sswan":
		data, err := sswanProfile(id, p.opts.ServerID, p12)
		if err != nil {
			return "", nil, err
		}
		return base + ".sswan", data, nil
	default:
		return "", nil, fmt.Errorf("unknown profile format %q", format)
	}
}

// EnsureServer provisions strongSwan: CA, server cert/key, swanctl config,
// then loads them and enables the service.
func (p *Provider) EnsureServer(ctx context.Context, pushRoutes []string, redirectGateway bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ca, err := p.getCA(ctx)
	if err != nil {
		return err
	}
	// ServerID is commonly a bare IP (no-domain VPS deployments). It has to
	// land in the right SAN bucket -- IP clients like strongSwan auto-type
	// a dotted-quad remote id as ID_IPV4_ADDR and refuse to trust a cert
	// whose SAN only has it as a DNS-type entry ("no trusted RSA public
	// key found for <ip>"), confirmed live against the load-test client.
	var dnsNames []string
	var ips []net.IP
	if p.opts.ServerID != "" {
		if ip := net.ParseIP(p.opts.ServerID); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, p.opts.ServerID)
		}
	}
	certPEM, keyPEM, err := ca.IssueServer(p.opts.ServerID, dnsNames, ips, leafValidity)
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}

	files := map[string]string{
		p.opts.SwanctlDir + "/x509ca/ca.crt":      ca.CACertPEM(),
		p.opts.SwanctlDir + "/x509/server.crt":    certPEM,
		p.opts.SwanctlDir + "/private/server.key": keyPEM,
	}
	for _, d := range []string{"/x509ca", "/x509", "/private", "/conf.d", "/x509crl"} {
		if _, err := p.opts.SSH.Run(ctx, "mkdir -p "+shellQuote(p.opts.SwanctlDir+d)); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	for path, content := range files {
		if err := p.opts.SSH.WriteFile(ctx, path, content); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	// A brand-new file WriteFile creates gets whatever mode the remote
	// shell's umask leaves it at (commonly 644) -- fine for the two certs
	// above, not for the private key. See openvpn/provider.go's own
	// EnsureServer for the identical reasoning.
	if _, err := p.opts.SSH.Run(ctx, "chmod 600 "+shellQuote(p.opts.SwanctlDir+"/private/server.key")); err != nil {
		return fmt.Errorf("chmod server.key: %w", err)
	}
	// Write the CRL (possibly empty) so revocation checking has a file to read.
	if err := p.rebuildCRL(ctx, ca); err != nil {
		return fmt.Errorf("build CRL: %w", err)
	}
	// Persist the routes so a later peer add/update/remove can regenerate the
	// swanctl config (per-client site connections) without recomputing them.
	if err := p.opts.Store.SaveServerRoutes(ctx, p.opts.Instance, pushRoutes, redirectGateway); err != nil {
		return fmt.Errorf("save server routes: %w", err)
	}
	if _, err := vpn.NewInstaller(p.opts.SSH).Service(ctx, "enable", p.opts.ServiceName); err != nil {
		return fmt.Errorf("enable service: %w", err)
	}
	// Render connections (base road-warrior + per-site clients) and load.
	if err := p.writeConnAndLoad(ctx, pushRoutes, redirectGateway); err != nil {
		return err
	}
	return nil
}

// writeConnAndLoad renders the swanctl connections file (shared road-warrior
// connection + a dedicated connection per site client advertising its LAN
// subnets) and reloads strongSwan.
func (p *Provider) writeConnAndLoad(ctx context.Context, pushRoutes []string, egress bool) error {
	localTS := append([]string(nil), pushRoutes...)
	if egress {
		localTS = append(localTS, "0.0.0.0/0")
	}

	cns, _, subnets, _, err := p.opts.Store.ListClients(ctx, p.opts.Instance)
	if err != nil {
		return err
	}
	var sites []SiteClient
	for i, cn := range cns {
		if subnets[i] == "" {
			continue
		}
		sites = append(sites, SiteClient{CN: cn, Subnets: strings.Split(subnets[i], ",")})
	}

	conf := ServerParams{
		ConnName: p.opts.ConnName, ServerID: p.opts.ServerID, Pool: p.opts.Pool,
		DNS: p.opts.DNS, LocalTS: localTS, CACertFile: "ca.crt", ServerCert: "server.crt",
		SiteClients: sites,
	}
	if err := p.opts.SSH.WriteFile(ctx, p.opts.SwanctlDir+"/conf.d/"+p.opts.ConnName+".conf", conf.RenderConnections()); err != nil {
		return fmt.Errorf("write swanctl conf: %w", err)
	}
	// charon reporting "active" via systemd doesn't guarantee its vici
	// plugin has bound /run/charon.vici yet (Type=simple, no readiness
	// notification for that specific milestone) -- confirmed live,
	// consistently racing on ALT Linux right after EnsureServer's own
	// "enable" call, though the same race could in principle hit any
	// distro under enough load. Retry briefly rather than fail outright
	// on what's usually a sub-second startup window.
	for attempt := 0; attempt < 5; attempt++ {
		_, err = p.opts.SSH.Run(ctx, "sudo swanctl --load-all")
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "connecting to") {
			break // a real config/credential error -- retrying won't help
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("swanctl load-all: %w", err)
}

// applyClients regenerates the swanctl connections from the persisted routes so
// site-client subnet changes take effect. No-op (config-wise) until the server
// has been provisioned (routes persisted). Caller holds p.mu.
func (p *Provider) applyClients(ctx context.Context) error {
	pushRoutes, egress, ok, err := p.opts.Store.GetServerRoutes(ctx, p.opts.Instance)
	if err != nil {
		return err
	}
	if !ok {
		return nil // server not provisioned yet; conf written at EnsureServer
	}
	return p.writeConnAndLoad(ctx, pushRoutes, egress)
}

// --- helpers ---

func splitAllowedIPs(allowed []string) (address string, subnets []string) {
	for _, a := range allowed {
		if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") {
			if address == "" {
				address = a
			}
			continue
		}
		subnets = append(subnets, a)
	}
	return address, subnets
}

func randPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
