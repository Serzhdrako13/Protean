package ikev2

import "strings"

// ActiveSA is a connected IKEv2 client, keyed by its remote identity (the
// client cert CN, with any "CN=" DN prefix already stripped -- see
// ParseListSAs).
type ActiveSA struct {
	RemoteID string
	Remote   string // remote host:port
	VIP      string // virtual IP assigned to the client from our pool, if any
}

// ParseListSAs best-effort-parses `swanctl --list-sas` human output. The
// format is line-oriented; an established SA block looks roughly like:
//
//	protean: #12, ESTABLISHED, IKEv2, ...
//	  local  'vpn.example.com' @ 203.0.113.10[4500]
//	  remote 'CN=office-a' @ 198.51.100.9[4500] [10.9.0.5]
//
// We collect the remote identity of blocks that reached ESTABLISHED. This is
// deliberately lenient -- strongSwan's exact wording varies by version, so we
// key on the stable "ESTABLISHED" marker and the "remote '<id>'" line. A
// cert-based client's identity always prints as the full "CN=<name>" DN
// (confirmed live), not the bare name our peers are stored under -- stripped
// here so callers can match RemoteID against a stored CN directly. Provider.
// ListPeers previously compared the raw "CN=<name>" against the bare stored
// CN and never matched, so no ikev2 client ever showed as online. The
// trailing "[<vip> ...]" (present only once a pool address was actually
// assigned to a road-warrior client, i.e. the CHILD_SA is really up, not
// just the IKE_SA) was never captured either -- confirmed against
// strongSwan's own list_sas.c source (the vici "remote-vips" field is
// appended to this same line as " [%s]") -- so no ikev2 client ever showed
// an address, even while genuinely connected.
func ParseListSAs(output string) []ActiveSA {
	var sas []ActiveSA
	established := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.Contains(line, "ESTABLISHED") {
			established = true
			continue
		}
		if !established {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "remote"); ok {
			id, remote, vip := parseIdentityLine(rest)
			id = strings.TrimPrefix(id, "CN=")
			if id != "" {
				sas = append(sas, ActiveSA{RemoteID: id, Remote: remote, VIP: vip})
			}
			established = false // consumed this block's remote
		}
	}
	return sas
}

// parseIdentityLine extracts the quoted identity, the "@ host[port]" part,
// and an optional trailing "[<vip> ...]" (first VIP only -- a client can in
// principle get more than one, but Protean only ever assigns a /32 or a
// single pool lease) from a strongSwan local/remote line remainder.
func parseIdentityLine(s string) (id, remote, vip string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "'"); i >= 0 {
		if j := strings.Index(s[i+1:], "'"); j >= 0 {
			id = s[i+1 : i+1+j]
			rest := strings.TrimSpace(s[i+1+j+1:])
			remote = strings.TrimPrefix(rest, "@ ")
		}
	}
	// " [" (space then bracket), not bare "[" -- the host[port] part right
	// before it is already bracketed with no space, and would otherwise
	// match first.
	if k := strings.Index(remote, " ["); k >= 0 {
		if l := strings.Index(remote[k+2:], "]"); l >= 0 {
			vips := strings.TrimSpace(remote[k+2 : k+2+l])
			if fields := strings.Fields(vips); len(fields) > 0 {
				vip = fields[0]
			}
			remote = strings.TrimSpace(remote[:k])
		}
	}
	return id, remote, vip
}
