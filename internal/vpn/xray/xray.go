// Package xray implements a modular set of Xray-core "strategies" for the
// DPI-resistant provider. Each strategy is ONE vetted, end-to-end config combo
// (transport + security + protocol), not a kit of parts: the operator picks a
// strategy, fills its parameters, and the panel generates both the server-side
// Xray inbound and the client share-link. New circumstances -> a new strategy
// module (compile-time registered), so invalid combinations never reach a host.
package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
)

// ParamSpec describes one operator-supplied parameter of a strategy.
type ParamSpec struct {
	Key         string
	Label       string
	Placeholder string
	Default     string
	Required    bool
	Secret      bool // rendered as a password field; not echoed back
}

// Params holds operator-supplied values keyed by ParamSpec.Key.
type Params map[string]string

func (p Params) get(key, def string) string {
	if v, ok := p[key]; ok && v != "" {
		return v
	}
	return def
}

// Value returns the parameter value for key (empty if unset). Exported for the
// UI layer to pre-fill forms.
func (p Params) Value(key string) string { return p[key] }

// Client is one credential on an Xray instance (multiple clients share the
// same transport/strategy). UUID is used by VLESS/VMess; Password by
// Trojan/Shadowsocks.
type Client struct {
	Name     string
	UUID     string
	Password string
}

// CredKind reports which credential field a strategy uses for its clients.
type CredKind int

const (
	CredUUID CredKind = iota
	CredPassword
)

// Strategy is one vetted Xray config combo. Implementations are stateless and
// registered via Register in their init().
type Strategy interface {
	// Name is the stable slug (e.g. "reality-vless-tcp").
	Name() string
	// Label is the human-readable name for the UI.
	Label() string
	// Params lists the operator-supplied (transport) parameters.
	Params() []ParamSpec
	// Cred reports the per-client credential kind (uuid or password).
	Cred() CredKind
	// MultiClient reports whether the strategy supports more than one client.
	MultiClient() bool
	// BuildInbound produces the Xray inbound object for the given clients
	// (ready for json.Marshal into the server config "inbounds" array).
	BuildInbound(p Params, clients []Client) (map[string]any, error)
	// ClientLink produces a share link for one client, given the public host.
	ClientLink(p Params, c Client, host string) (string, error)
}

var registry = map[string]Strategy{}

// Register adds a strategy to the compile-time registry (called from init()).
func Register(s Strategy) { registry[s.Name()] = s }

// Get returns a registered strategy by name.
func Get(name string) (Strategy, bool) { s, ok := registry[name]; return s, ok }

// All returns every registered strategy, sorted by name for stable UIs.
func All() []Strategy {
	out := make([]Strategy, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// --- shared helpers ---

// NewUUID returns a random RFC-4122 v4 UUID (used as the client id for
// VLESS/VMess).
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RealityKeypair is an X25519 keypair for VLESS+Reality: the private key stays
// in the server config, the public key goes into the client link.
type RealityKeypair struct {
	PrivateKey string // base64 raw-url
	PublicKey  string // base64 raw-url
}

// GenRealityKeypair generates an X25519 keypair encoded the way Xray expects
// (base64 raw-url, no padding).
func GenRealityKeypair() (RealityKeypair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityKeypair{}, err
	}
	enc := base64.RawURLEncoding
	return RealityKeypair{
		PrivateKey: enc.EncodeToString(priv.Bytes()),
		PublicKey:  enc.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// NewShortID returns a random Reality shortId (hex, 8 bytes).
func NewShortID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewPassword returns a random password (hex, n bytes) for Trojan/Shadowsocks.
func NewPassword(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func requireParams(p Params, specs []ParamSpec) error {
	for _, s := range specs {
		if s.Required && p.get(s.Key, s.Default) == "" {
			return fmt.Errorf("missing required parameter %q", s.Key)
		}
	}
	return nil
}
