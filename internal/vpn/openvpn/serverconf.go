package openvpn

import (
	"fmt"
	"sort"
	"strings"
)

// ServerParams describes an OpenVPN server instance the panel manages. Cert
// material is written to sibling files referenced by the generated config.
type ServerParams struct {
	Port       int
	Proto      string // udp | tcp
	Dev        string // tun
	ServerNet  string // e.g. "10.8.0.0"
	ServerMask string // e.g. "255.255.255.0"
	DNS        []string
	// TunMTU/Mssfix: 0 = leave unset (OpenVPN's own default). tun-mtu changes
	// the tunnel device's MTU; mssfix clamps TCP MSS instead -- distinct
	// knobs, both used for the same problem (mobile/PPPoE/nested-tunnel
	// networks silently fragmenting/black-holing large packets).
	TunMTU int
	Mssfix int
	// PushRoutes are extra networks pushed to clients (mesh tunnels + site
	// subnets + optionally a default route for internet egress).
	PushRoutes      []string
	RedirectGateway bool // internet egress
	// File paths on the host for the inlined-at-runtime material.
	CACertPath      string
	ServerCert      string
	ServerKey       string
	TLSCryptKey     string
	DHPath          string // empty when using ECDH/none
	ClientConfigDir string
	StatusPath      string
	CRLPath         string // crl-verify path; clients on this CRL are refused
	Cipher          string
	// LegacyCipher: true emits the older single "cipher <name>" directive
	// instead of "data-ciphers"/"data-ciphers-fallback" (introduced in
	// OpenVPN 2.5) -- needed for any still-deployed OpenVPN 2.4.x host
	// (confirmed live: Astra Linux CE 2.12's own repo only carries
	// 2.4.7, which rejects "data-ciphers" outright as an unrecognized
	// option and refuses to start at all). Set by the caller after
	// detecting the installed server's actual version, not guessed here.
	LegacyCipher bool
}

// Defaults fills unset fields with sensible values.
func (p *ServerParams) Defaults() {
	if p.Proto == "" {
		p.Proto = "udp"
	}
	if p.Dev == "" {
		p.Dev = "tun"
	}
	if p.Cipher == "" {
		p.Cipher = "AES-256-GCM"
	}
}

// Render produces an OpenVPN server config file.
func (p ServerParams) Render() string {
	p.Defaults()
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("# Managed by Protean. Manual edits may be overwritten.")
	w("port %d", p.Port)
	w("proto %s", p.Proto)
	w("dev %s", p.Dev)
	w("topology subnet")
	w("server %s %s", p.ServerNet, p.ServerMask)
	if p.TunMTU > 0 {
		w("tun-mtu %d", p.TunMTU)
	}
	if p.Mssfix > 0 {
		w("mssfix %d", p.Mssfix)
	}
	w("ca %s", p.CACertPath)
	w("cert %s", p.ServerCert)
	w("key %s", p.ServerKey)
	if p.DHPath != "" {
		w("dh %s", p.DHPath)
	} else {
		w("dh none")
	}
	if p.TLSCryptKey != "" {
		w("tls-crypt %s", p.TLSCryptKey)
	}
	if p.CRLPath != "" {
		w("crl-verify %s", p.CRLPath)
	}
	if p.LegacyCipher {
		w("cipher %s", p.Cipher)
	} else {
		w("data-ciphers %s", p.Cipher)
		w("data-ciphers-fallback %s", p.Cipher)
	}
	if p.ClientConfigDir != "" {
		w("client-config-dir %s", p.ClientConfigDir)
	}
	// Let clients talk to each other/subnets via this server.
	w("client-to-client")
	w("keepalive 10 60")
	w("persist-key")
	w("persist-tun")
	if p.StatusPath != "" {
		w("status %s", p.StatusPath)
		w("status-version 2")
	}
	for _, dns := range p.DNS {
		w(`push "dhcp-option DNS %s"`, dns)
	}
	if p.RedirectGateway {
		w(`push "redirect-gateway def1 bypass-dhcp"`)
	}
	// Deterministic route order for stable diffs/backups.
	routes := append([]string(nil), p.PushRoutes...)
	sort.Strings(routes)
	for _, r := range routes {
		if net, mask, ok := cidrToNetMask(r); ok {
			w(`push "route %s %s"`, net, mask)
		}
	}
	w("verb 3")
	return b.String()
}
