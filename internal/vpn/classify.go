package vpn

import (
	"net"
	"strings"
)

// PeerRouteClass is the result of classifying one peer's AllowedIPs against
// its interface's own tunnel network -- see ClassifyPeerRoutes.
type PeerRouteClass struct {
	// OwnAddress is the peer's own tunnel identity (e.g. "10.10.0.5/32"),
	// empty if none could be confidently identified.
	OwnAddress string
	// SiteSubnets are AllowedIPs entries outside the tunnel network -- real
	// networks reachable THROUGH this peer (it's acting as a router/site),
	// not the peer's own address.
	SiteSubnets []string
	// FullTunnel is true if "0.0.0.0/0" and/or "::/0" was present -- a
	// client-side "route everything through the VPN" directive, never a
	// real routed site subnet.
	FullTunnel bool
	// Anomalies are entries that couldn't be confidently classified either
	// way (unparsable, a second own-address candidate, a wide entry that's
	// still inside the tunnel network) -- never silently dropped, so a
	// caller can always surface them for a human to look at.
	Anomalies []string
}

// ClassifyPeerRoutes splits a peer's AllowedIPs against tunnelCIDR (the
// interface's own network, e.g. from the server's configured Address) to
// tell "this is the peer's own tunnel address" apart from "this is a
// subnet the peer routes traffic for" -- the same underlying data
// (AllowedIPs) represents two conceptually different things, and
// conflating them (e.g. joining every entry into one display string) is a
// real bug this function exists to stop happening again.
//
// Deliberately NOT position- or mask-width-only based (contrast
// openvpn.splitClientAllowedIPs, which assumes the first entry is always
// the client's own address and is safe there only because the panel
// itself always assigns that address inside the single server subnet by
// construction). A wg-family peer adopted from an arbitrary hand-written
// conf carries no such guarantee -- nothing stops a hand-authored entry
// from listing the site subnet before the peer's own address, or a /32
// from a completely unrelated range. Classification is therefore anchored
// to actual containment within tunnelCIDR, not position or mask width
// alone.
//
// Rules, applied per entry:
//   - "0.0.0.0/0" or "::/0" -> FullTunnel = true, never a site subnet.
//   - unparsable -> Anomalies, otherwise ignored.
//   - a host address (/32 or /128) contained in tunnelCIDR -> candidate
//     own address; a second candidate is an Anomaly, not silently
//     overwritten.
//   - a wider entry still contained in tunnelCIDR (the peer claims a
//     chunk of the tunnel network itself, not just its own host) ->
//     Anomaly, not auto-classified either way -- unusual enough that a
//     guess is more likely wrong than a client's fat-fingered mask.
//   - anything not contained in tunnelCIDR (any width) -> SiteSubnets.
//
// If tunnelCIDR itself doesn't parse (down interface, no address yet),
// every entry is reported as an Anomaly rather than guessed at.
func ClassifyPeerRoutes(tunnelCIDR string, allowedIPs []string) PeerRouteClass {
	var class PeerRouteClass

	_, tunnelNet, err := net.ParseCIDR(tunnelCIDR)
	if err != nil {
		for _, raw := range allowedIPs {
			a := strings.TrimSpace(raw)
			if a == "" {
				continue
			}
			class.Anomalies = append(class.Anomalies, "no usable tunnel network to classify "+a+" against")
		}
		return class
	}
	tunnelOnes, _ := tunnelNet.Mask.Size()

	for _, raw := range allowedIPs {
		a := strings.TrimSpace(raw)
		if a == "" {
			continue
		}
		if a == "0.0.0.0/0" || a == "::/0" {
			class.FullTunnel = true
			continue
		}
		ip, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			class.Anomalies = append(class.Anomalies, "unparsable AllowedIPs entry: "+a)
			continue
		}
		ones, bits := ipnet.Mask.Size()
		isHost := ones == bits
		contained := tunnelNet.Contains(ip) && ones >= tunnelOnes

		switch {
		case isHost && contained:
			if class.OwnAddress == "" {
				class.OwnAddress = a
			} else {
				class.Anomalies = append(class.Anomalies, "multiple candidate own addresses: "+class.OwnAddress+" and "+a)
			}
		case contained:
			class.Anomalies = append(class.Anomalies, "entry "+a+" is inside the tunnel network but isn't a host address -- not auto-classified")
		default:
			class.SiteSubnets = append(class.SiteSubnets, a)
		}
	}
	return class
}
