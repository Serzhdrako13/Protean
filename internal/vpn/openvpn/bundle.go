package openvpn

import (
	"fmt"
	"strings"
)

// BundleParams is everything needed to build a client .ovpn with inlined
// credentials -- a single file the user imports.
type BundleParams struct {
	RemoteHost    string
	RemotePort    int
	Proto         string // udp | tcp
	Dev           string // tun
	Cipher        string
	// TunMTU/Mssfix mirror ServerParams' fields of the same name -- the
	// client side needs matching values, tun-mtu isn't something the server
	// can push. 0 = leave unset.
	TunMTU        int
	Mssfix        int
	CACertPEM     string
	ClientCertPEM string
	ClientKeyPEM  string
	TLSCryptPEM   string
}

// Build assembles the .ovpn text with inline <ca>/<cert>/<key>/<tls-crypt>.
func (p BundleParams) Build() string {
	proto := p.Proto
	if proto == "" {
		proto = "udp"
	}
	dev := p.Dev
	if dev == "" {
		dev = "tun"
	}
	cipher := p.Cipher
	if cipher == "" {
		cipher = "AES-256-GCM"
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("client")
	w("dev %s", dev)
	w("proto %s", proto)
	w("remote %s %d", p.RemoteHost, p.RemotePort)
	if p.TunMTU > 0 {
		w("tun-mtu %d", p.TunMTU)
	}
	if p.Mssfix > 0 {
		w("mssfix %d", p.Mssfix)
	}
	w("resolv-retry infinite")
	w("nobind")
	w("persist-key")
	w("persist-tun")
	w("remote-cert-tls server")
	w("data-ciphers %s", cipher)
	w("data-ciphers-fallback %s", cipher)
	w("verb 3")

	inline := func(tag, pem string) {
		pem = strings.TrimRight(pem, "\n")
		fmt.Fprintf(&b, "<%s>\n%s\n</%s>\n", tag, pem, tag)
	}
	inline("ca", p.CACertPEM)
	inline("cert", p.ClientCertPEM)
	if p.ClientKeyPEM != "" {
		inline("key", p.ClientKeyPEM)
	} else {
		// CSR-based enrollment: the client holds its own private key.
		w("# This profile was issued from your CSR; the private key stays on")
		w("# your device. Add it, e.g.:  key /path/to/your.key")
	}
	if p.TLSCryptPEM != "" {
		inline("tls-crypt", p.TLSCryptPEM)
	}
	return b.String()
}
