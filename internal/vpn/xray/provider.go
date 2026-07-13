package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"protean/internal/vpn"
)

// SSH is the remote-exec surface (satisfied by *sshexec.Client).
type SSH interface {
	Run(ctx context.Context, cmd string) (string, error)
	ReadFile(ctx context.Context, path string) (string, error)
	WriteFile(ctx context.Context, path, content string) error
}

// Sealer encrypts/decrypts secret material at rest (satisfied by *auth.Encryptor).
type Sealer interface {
	Seal(plaintext string) ([]byte, error)
	Open(blob []byte) (string, error)
}

// ClientRow is one stored client (name + encrypted credential blob).
type ClientRow struct {
	Name    string
	EncCred []byte
}

// Store persists the Xray instance (strategy+params+relay) and its clients.
type Store interface {
	SaveInstance(ctx context.Context, provider, strategy string, encParams, encRelay []byte) error
	GetInstance(ctx context.Context, provider string) (strategy string, encParams, encRelay []byte, err error)
	SaveXrayClient(ctx context.Context, provider, name string, encCred []byte) error
	ListXrayClients(ctx context.Context, provider string) ([]ClientRow, error)
	DeleteXrayClient(ctx context.Context, provider, name string) error
}

type Options struct {
	Instance    string
	ConfigPath  string
	ServiceName string
	PublicHost  string
	SSH         SSH
	Store       Store
	Enc         Sealer
}

type Provider struct {
	opts Options
}

func New(opts Options) *Provider {
	if opts.Instance == "" {
		opts.Instance = "xray"
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = "/usr/local/etc/xray/config.json"
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "xray"
	}
	return &Provider{opts: opts}
}

func (p *Provider) Name() string        { return p.opts.Instance }
func (p *Provider) Type() string        { return "xray" }
func (p *Provider) ServiceName() string { return p.opts.ServiceName }

func (p *Provider) Status(ctx context.Context) (vpn.ServerStatus, error) {
	st := vpn.ServerStatus{Provider: p.opts.Instance}
	out, _ := p.opts.SSH.Run(ctx, "systemctl is-active "+shellQuote(p.opts.ServiceName))
	st.Up = strings.TrimSpace(out) == "active"
	if strategy, _, _, err := p.opts.Store.GetInstance(ctx, p.opts.Instance); err == nil {
		st.Extra = map[string]string{"strategy": strategy}
		// A client can't be "online" (or even reachably configured) through
		// a stopped service -- only count when the systemd unit is actually
		// active, matching wg-family's Status() (which returns before ever
		// touching peers/handshakes when down). Previously this ran
		// unconditionally, so a fully-stopped Xray instance could still
		// report e.g. "1/1 online".
		if st.Up {
			clients, _ := p.listClients(ctx)
			st.PeerCount = len(clients)
			st.PeersOnline = len(clients)
		}
	}
	if p.opts.PublicHost != "" {
		st.Endpoint = p.opts.PublicHost
	}
	return st, nil
}

// Xray is configured via its own page; peer-based methods are unused.
func (p *Provider) ListPeers(context.Context) ([]vpn.Peer, error) { return nil, nil }
func (p *Provider) AddPeer(context.Context, vpn.PeerSpec) (vpn.NewPeerResult, error) {
	return vpn.NewPeerResult{}, vpn.ErrNotImplemented
}
func (p *Provider) UpdatePeer(context.Context, string, vpn.PeerSpec) error {
	return vpn.ErrNotImplemented
}
func (p *Provider) RemovePeer(context.Context, string) error { return vpn.ErrNotImplemented }
func (p *Provider) UpdateServerConfig(context.Context, vpn.ServerConfig) error {
	return fmt.Errorf("use the Xray page to configure the strategy")
}

// Apply provisions/updates the instance: it saves the strategy+params(+relay
// chain), ensures instance crypto (Reality keys) and at least one client, then
// rebuilds the on-host config and restarts the service. An empty/nil relays
// means direct egress; a non-empty ordered slice chains hop 0 -> hop 1 -> ...
func (p *Provider) Apply(ctx context.Context, strategyName string, params Params, relays []RelaySpec) error {
	if _, ok := Get(strategyName); !ok {
		return fmt.Errorf("unknown strategy %q", strategyName)
	}
	if params == nil {
		params = Params{}
	}
	// Preserve instance crypto across re-applies of the same strategy.
	if cur, curParams, _, err := p.instance(ctx); err == nil && cur == strategyName {
		for _, k := range instanceCryptoKeys {
			if curParams.get(k, "") != "" && params.get(k, "") == "" {
				params[k] = curParams[k]
			}
		}
	}
	if err := ensureInstanceCrypto(strategyName, params); err != nil {
		return err
	}
	if err := p.persistInstance(ctx, strategyName, params, relays); err != nil {
		return err
	}
	// Ensure at least one client so the config is valid.
	clients, err := p.listClients(ctx)
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		if err := p.AddClient(ctx, "default"); err != nil {
			return err
		}
	}
	return p.rebuild(ctx)
}

// AddClient generates a credential for a new client and rebuilds the config.
func (p *Provider) AddClient(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("client name required")
	}
	strategyName, _, _, err := p.instance(ctx)
	if err != nil {
		return fmt.Errorf("configure a strategy first: %w", err)
	}
	strat, _ := Get(strategyName)
	if !strat.MultiClient() {
		if cs, _ := p.listClients(ctx); len(cs) >= 1 {
			return fmt.Errorf("strategy %q supports a single client", strategyName)
		}
	}
	c := Client{Name: name}
	switch strat.Cred() {
	case CredUUID:
		if c.UUID, err = NewUUID(); err != nil {
			return err
		}
	case CredPassword:
		if c.Password, err = NewPassword(16); err != nil {
			return err
		}
	}
	if err := p.saveClient(ctx, c); err != nil {
		return err
	}
	return p.rebuild(ctx)
}

// RemoveClient deletes a client and rebuilds the config.
func (p *Provider) RemoveClient(ctx context.Context, name string) error {
	if err := p.opts.Store.DeleteXrayClient(ctx, p.opts.Instance, name); err != nil {
		return err
	}
	return p.rebuild(ctx)
}

// ClientLinkView is a client's name + share link for the UI.
type ClientLinkView struct {
	Name string
	Link string
}

// ClientLinks returns share links for all clients.
func (p *Provider) ClientLinks(ctx context.Context) ([]ClientLinkView, error) {
	strategyName, params, _, err := p.instance(ctx)
	if err != nil {
		return nil, err
	}
	strat, ok := Get(strategyName)
	if !ok {
		return nil, fmt.Errorf("unknown strategy %q", strategyName)
	}
	clients, err := p.listClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]ClientLinkView, 0, len(clients))
	for _, c := range clients {
		link, err := strat.ClientLink(params, c, p.opts.PublicHost)
		if err != nil {
			return nil, err
		}
		out = append(out, ClientLinkView{Name: c.Name, Link: link})
	}
	return out, nil
}

// Subscription returns a base64 subscription body (newline-joined links), the
// format Happ/v2rayN/nekoray import.
func (p *Provider) Subscription(ctx context.Context) (string, error) {
	links, err := p.ClientLinks(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, l := range links {
		b.WriteString(l.Link)
		b.WriteString("\n")
	}
	return base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}

// Current returns the stored strategy, params and relay chain (ordered; empty
// means direct egress).
func (p *Provider) Current(ctx context.Context) (strategy string, params Params, relays []RelaySpec, err error) {
	return p.instance(ctx)
}

// --- internal ---

func (p *Provider) rebuild(ctx context.Context) error {
	strategyName, params, relays, err := p.instance(ctx)
	if err != nil {
		return err
	}
	strat, ok := Get(strategyName)
	if !ok {
		return fmt.Errorf("unknown strategy %q", strategyName)
	}
	clients, err := p.listClients(ctx)
	if err != nil {
		return err
	}
	inbound, err := strat.BuildInbound(params, clients)
	if err != nil {
		return err
	}
	var relayOuts []Outbound
	for _, r := range relays {
		if r.Strategy == "" {
			continue
		}
		out, err := BuildRelayOutbound(r)
		if err != nil {
			return err
		}
		relayOuts = append(relayOuts, out)
	}
	conf, err := BuildServerConfig([]map[string]any{inbound}, relayOuts)
	if err != nil {
		return err
	}
	if err := p.opts.SSH.WriteFile(ctx, p.opts.ConfigPath, string(conf)); err != nil {
		return fmt.Errorf("write xray config: %w", err)
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

func (p *Provider) instance(ctx context.Context) (string, Params, []RelaySpec, error) {
	strategy, encParams, encRelay, err := p.opts.Store.GetInstance(ctx, p.opts.Instance)
	if err != nil {
		return "", nil, nil, err
	}
	pj, err := p.opts.Enc.Open(encParams)
	if err != nil {
		return "", nil, nil, err
	}
	params := Params{}
	if err := json.Unmarshal([]byte(pj), &params); err != nil {
		return "", nil, nil, err
	}
	var relays []RelaySpec
	if len(encRelay) > 0 {
		rj, err := p.opts.Enc.Open(encRelay)
		if err != nil {
			return "", nil, nil, err
		}
		if relays, err = decodeRelayChain([]byte(rj)); err != nil {
			return "", nil, nil, err
		}
	}
	return strategy, params, relays, nil
}

// decodeRelayChain unmarshals the stored relay blob as an ordered chain
// ([]RelaySpec). Rows saved before N-hop chaining shipped hold a single
// RelaySpec JSON object instead of an array -- fall back to that shape and
// wrap it as a 1-element chain so existing single-relay instances keep
// working unmodified after deploy.
func decodeRelayChain(raw []byte) ([]RelaySpec, error) {
	var chain []RelaySpec
	if err := json.Unmarshal(raw, &chain); err == nil {
		return chain, nil
	}
	var single RelaySpec
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, err
	}
	if single.Strategy == "" {
		return nil, nil
	}
	return []RelaySpec{single}, nil
}

func (p *Provider) persistInstance(ctx context.Context, strategy string, params Params, relays []RelaySpec) error {
	pj, _ := json.Marshal(params)
	encParams, err := p.opts.Enc.Seal(string(pj))
	if err != nil {
		return err
	}
	var encRelay []byte
	if len(relays) > 0 {
		rj, _ := json.Marshal(relays)
		if encRelay, err = p.opts.Enc.Seal(string(rj)); err != nil {
			return err
		}
	}
	return p.opts.Store.SaveInstance(ctx, p.opts.Instance, strategy, encParams, encRelay)
}

func (p *Provider) saveClient(ctx context.Context, c Client) error {
	cj, _ := json.Marshal(c)
	enc, err := p.opts.Enc.Seal(string(cj))
	if err != nil {
		return err
	}
	return p.opts.Store.SaveXrayClient(ctx, p.opts.Instance, c.Name, enc)
}

func (p *Provider) listClients(ctx context.Context) ([]Client, error) {
	rows, err := p.opts.Store.ListXrayClients(ctx, p.opts.Instance)
	if err != nil {
		return nil, err
	}
	out := make([]Client, 0, len(rows))
	for _, r := range rows {
		cj, err := p.opts.Enc.Open(r.EncCred)
		if err != nil {
			return nil, err
		}
		var c Client
		if err := json.Unmarshal([]byte(cj), &c); err != nil {
			return nil, err
		}
		c.Name = r.Name
		out = append(out, c)
	}
	return out, nil
}

// ensureInstanceCrypto fills instance-level secret params (Reality keys + short
// id). Per-client credentials are generated in AddClient.
func ensureInstanceCrypto(strategyName string, p Params) error {
	if strategyName == "reality-vless-tcp" {
		if p.get(pRealityPriv, "") == "" {
			kp, err := GenRealityKeypair()
			if err != nil {
				return err
			}
			p[pRealityPriv] = kp.PrivateKey
			p[pRealityPub] = kp.PublicKey
		}
		if p.get(pShortID, "") == "" {
			sid, err := NewShortID()
			if err != nil {
				return err
			}
			p[pShortID] = sid
		}
	}
	return nil
}

var instanceCryptoKeys = []string{pRealityPriv, pRealityPub, pShortID}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
