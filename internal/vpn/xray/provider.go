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
// rebuilds the on-host config and restarts the service.
//
// relays distinguishes "the caller didn't send a relay chain at all" (nil)
// from "set it to exactly this, including clearing it" (non-nil, possibly
// pointing to an empty/nil slice for direct egress). This matters because
// relay links are write-only (like the secret params handled just below) --
// GET never returns the actual link, only host+strategy per hop, so the
// admin's edit form always starts with blank inputs regardless of whether
// a chain already exists. Before this distinction existed, submitting the
// form with those blanks untouched (any routine params-only edit) silently
// wiped an already-configured relay chain back to direct egress -- a real
// incident, and a worse one than most such bugs: reverting a deliberately
// chained-egress setup to direct egress isn't just data loss, it can
// undermine the whole reason that chain existed. A nil relays here
// preserves whatever's already configured for the SAME strategy;
// switching strategy always starts the chain fresh, since a different
// strategy's hops may not even be meaningful together.
func (p *Provider) Apply(ctx context.Context, strategyName string, params Params, relays *[]RelaySpec) error {
	strat, ok := Get(strategyName)
	if !ok {
		return fmt.Errorf("unknown strategy %q", strategyName)
	}
	if params == nil {
		params = Params{}
	}
	curStrategy, curParams, curRelays, curErr := p.instance(ctx)
	sameStrategy := curErr == nil && curStrategy == strategyName

	if is, ok := strat.(InstanceSecrets); ok {
		specs := is.InstanceSecrets()
		// Preserve instance secrets across re-applies of the same strategy.
		if sameStrategy {
			for _, k := range secretParamKeys(specs) {
				if curParams.get(k, "") != "" && params.get(k, "") == "" {
					params[k] = curParams[k]
				}
			}
		}
		if err := ensureInstanceCrypto(specs, params); err != nil {
			return err
		}
	}

	var finalRelays []RelaySpec
	if relays != nil {
		finalRelays = *relays
	} else if sameStrategy {
		finalRelays = curRelays
	}

	if err := p.persistInstance(ctx, strategyName, params, finalRelays); err != nil {
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

// ensureInstanceCrypto fills a strategy's declared instance-level secret
// params (e.g. Reality's keypair + short id) that are still empty. Per-client
// credentials are generated in AddClient, not here.
func ensureInstanceCrypto(specs []SecretSpec, p Params) error {
	for _, s := range specs {
		if p.get(s.Key, "") != "" {
			continue
		}
		switch s.Kind {
		case "reality_keypair":
			kp, err := GenRealityKeypair()
			if err != nil {
				return err
			}
			p[s.Key] = kp.PrivateKey
			p[s.PairKey] = kp.PublicKey
		case "short_id":
			sid, err := NewShortID()
			if err != nil {
				return err
			}
			p[s.Key] = sid
		case "uuid":
			u, err := NewUUID()
			if err != nil {
				return err
			}
			p[s.Key] = u
		case "password":
			pw, err := NewPassword(16)
			if err != nil {
				return err
			}
			p[s.Key] = pw
		default:
			return fmt.Errorf("unknown instance secret kind %q for key %q", s.Kind, s.Key)
		}
	}
	return nil
}

// secretParamKeys flattens SecretSpecs to the param keys they fill (Key, and
// PairKey when set), used to decide which params to carry over unchanged on
// a re-apply of the same strategy.
func secretParamKeys(specs []SecretSpec) []string {
	keys := make([]string, 0, len(specs)*2)
	for _, s := range specs {
		keys = append(keys, s.Key)
		if s.PairKey != "" {
			keys = append(keys, s.PairKey)
		}
	}
	return keys
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
