// Package clientconfig builds the .conf text and QR code handed to a
// client after a peer is created. It's deliberately separate from the
// provider implementations: which subnets a client should route through
// the tunnel is a policy decision the API layer makes (based on the
// registered subnets list), not something a wg-family provider has an
// opinion on.
package clientconfig

import (
	"fmt"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

type Params struct {
	ClientPrivateKey    string
	ClientAddress       string // e.g. "10.10.0.5/32"
	DNS                 string
	MTU                 int // 0 = omit, let the client app use its own default
	ServerPublicKey     string
	Endpoint            string // host:port
	AllowedIPs          []string
	PersistentKeepalive int
	Extra               map[string]string
}

func Build(p Params) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", p.ClientPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", p.ClientAddress)
	if p.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", p.DNS)
	}
	if p.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.MTU)
	}
	for k, v := range p.Extra {
		fmt.Fprintf(&b, "%s = %s\n", k, v)
	}

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", p.ServerPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
	if p.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
	}
	return b.String()
}

// QRPNG renders configText as a PNG QR code for scanning into a mobile
// WireGuard/AmneziaWG app.
func QRPNG(configText string) ([]byte, error) {
	return qrcode.Encode(configText, qrcode.Medium, 320)
}
