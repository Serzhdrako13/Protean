// Package ikev2 implements the vpn.Provider interface for IKEv2/IPsec via
// strongSwan's swanctl. Like OpenVPN it is certificate-based (see
// internal/vpn/pki); clients are exported as PKCS#12 bundles.
package ikev2

import (
	"fmt"
	"sort"
	"strings"
)

// ServerParams describes the swanctl connection the panel manages.
type ServerParams struct {
	ConnName string
	ServerID string // usually the public hostname/IP (cert SAN)
	Pool     string // client address pool, e.g. "10.9.0.0/24"
	DNS      []string
	// LocalTS are the traffic selectors offered to clients: site subnets +
	// (for full tunnel / egress) 0.0.0.0/0.
	LocalTS    []string
	CACertFile string // filename in swanctl/x509ca
	ServerCert string // filename in swanctl/x509
	// SiteClients get a dedicated connection matched on their cert identity,
	// advertising their own LAN subnet(s) as remote_ts (site-to-site). Clients
	// without subnets use the shared road-warrior connection.
	SiteClients []SiteClient
}

// SiteClient is a client that routes one or more LAN subnets (a site), so the
// server must accept those as its remote traffic selectors.
type SiteClient struct {
	CN      string
	Subnets []string
}

// RenderConnections produces the swanctl connections+pools config.
func (p ServerParams) RenderConnections() string {
	name := p.ConnName
	if name == "" {
		name = "protean"
	}
	localTS := p.LocalTS
	if len(localTS) == 0 {
		localTS = []string{"0.0.0.0/0"}
	}
	ts := append([]string(nil), localTS...)
	sort.Strings(ts)

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	const esp = "aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048"

	// conn renders one connection block. remoteID/remoteTS are empty for the
	// shared road-warrior connection and set for a dedicated site connection.
	conn := func(connName, remoteID, localTS, remoteTS string) {
		w("   %s {", connName)
		w("      version = 2")
		w("      pools = %s-pool", name)
		w("      local_addrs = %%any")
		w("      local {")
		w("         auth = pubkey")
		w("         certs = %s", p.ServerCert)
		w("         id = %s", p.ServerID)
		w("      }")
		w("      remote {")
		w("         auth = pubkey")
		w("         cacerts = %s", p.CACertFile)
		if remoteID != "" {
			w("         id = %s", remoteID)
		}
		w("      }")
		w("      children {")
		w("         net {")
		w("            local_ts = %s", localTS)
		if remoteTS != "" {
			w("            remote_ts = %s", remoteTS)
		}
		w("            esp_proposals = %s", esp)
		w("            start_action = none")
		w("         }")
		w("      }")
		w("      proposals = %s", esp)
		w("   }")
	}

	w("# Managed by Protean.")
	w("connections {")
	conn(name, "", strings.Join(ts, ","), "")
	// Per-site connections: matched on the client's cert CN, advertising the
	// client's LAN subnet(s) as remote_ts so the server routes to that site.
	// strongSwan prefers the more specific (id-matched) connection.
	sites := append([]SiteClient(nil), p.SiteClients...)
	sort.Slice(sites, func(i, j int) bool { return sites[i].CN < sites[j].CN })
	for _, sc := range sites {
		if len(sc.Subnets) == 0 || strings.TrimSpace(sc.CN) == "" {
			continue
		}
		rts := append([]string(nil), sc.Subnets...)
		sort.Strings(rts)
		conn(name+"-"+sanitizeName(sc.CN), sc.CN, strings.Join(ts, ","), strings.Join(rts, ","))
	}
	w("}")
	w("pools {")
	w("   %s-pool {", name)
	w("      addrs = %s", p.Pool)
	if len(p.DNS) > 0 {
		w("      dns = %s", strings.Join(p.DNS, ","))
	}
	w("   }")
	w("}")
	return b.String()
}
