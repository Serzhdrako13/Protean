package openvpn

import "net"

// cidrToNetMask converts "10.8.0.0/24" to ("10.8.0.0", "255.255.255.0").
// OpenVPN's `route`/`server` directives take dotted-quad masks, not prefix
// lengths. IPv6 CIDRs are returned unchanged in net with an empty mask and
// ok=false (callers handle v6 via `route-ipv6` separately if needed).
func cidrToNetMask(cidr string) (network, mask string, ok bool) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", false
	}
	if ipnet.IP.To4() == nil {
		return "", "", false // IPv4 only here
	}
	m := ipnet.Mask
	if len(m) != 4 {
		return "", "", false
	}
	return ipnet.IP.String(), net.IPv4(m[0], m[1], m[2], m[3]).String(), true
}
