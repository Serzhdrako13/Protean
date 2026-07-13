package ikev2

import "strings"

// ActiveSA is a connected IKEv2 client, keyed by its remote identity (the
// client cert CN).
type ActiveSA struct {
	RemoteID string
	Remote   string // remote host:port
}

// ParseListSAs best-effort-parses `swanctl --list-sas` human output. The
// format is line-oriented; an established SA block looks roughly like:
//
//	wgpanel: #12, ESTABLISHED, IKEv2, ...
//	  local  'vpn.example.com' @ 203.0.113.10[4500]
//	  remote 'office-a' @ 198.51.100.9[4500]
//
// We collect the remote identity of blocks that reached ESTABLISHED. This is
// deliberately lenient -- strongSwan's exact wording varies by version, so we
// key on the stable "ESTABLISHED" marker and the "remote '<id>'" line.
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
			id, remote := parseIdentityLine(rest)
			if id != "" {
				sas = append(sas, ActiveSA{RemoteID: id, Remote: remote})
			}
			established = false // consumed this block's remote
		}
	}
	return sas
}

// parseIdentityLine extracts the quoted identity and the "@ host[port]" part
// from a strongSwan local/remote line remainder.
func parseIdentityLine(s string) (id, remote string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "'"); i >= 0 {
		if j := strings.Index(s[i+1:], "'"); j >= 0 {
			id = s[i+1 : i+1+j]
			rest := strings.TrimSpace(s[i+1+j+1:])
			remote = strings.TrimPrefix(rest, "@ ")
		}
	}
	return id, remote
}
