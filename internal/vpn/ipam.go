package vpn

import (
	"fmt"
	"net"
	"strings"
)

// FirstCIDR returns the first comma-separated entry of a possibly dual-stack
// address string (e.g. "10.0.0.1/24, fd00::1/64"), trimmed. Used to pick the
// IPv4 net where a single address is needed.
func FirstCIDR(address string) string {
	if i := strings.IndexByte(address, ','); i >= 0 {
		address = address[:i]
	}
	return strings.TrimSpace(address)
}

// NextFreeIP finds an unused host address within cidr (e.g. "10.10.0.0/24"),
// skipping the network address and any IP already in used (bare IPs, no
// mask). It returns the suggestion as a /32 (IPv4) or /128 (IPv6), ready to
// drop straight into a peer's AllowedIPs.
func NextFreeIP(cidr string, used map[string]bool) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	maskBits := 32
	if ip.To4() == nil {
		maskBits = 128
	}

	for cur := cloneIP(ipnet.IP); ipnet.Contains(cur); incIP(cur) {
		if cur.Equal(ipnet.IP) { // network address
			continue
		}
		if !used[cur.String()] {
			return fmt.Sprintf("%s/%d", cur.String(), maskBits), nil
		}
	}
	return "", fmt.Errorf("no free address in %s", cidr)
}

// NextFreeIPInRange is NextFreeIP, additionally bounded to [rangeStart,
// rangeEnd] within cidr -- a per-provider "DHCP pool" style restriction, so
// auto-provisioning (portal access grants, node grants) never hands out an
// address from a part of the subnet reserved for static/manual use (e.g. a
// low range kept for routers with fixed automations). Empty rangeStart/
// rangeEnd means "start of subnet"/"end of subnet" respectively -- with
// both empty this is byte-for-byte the same scan as NextFreeIP.
func NextFreeIPInRange(cidr, rangeStart, rangeEnd string, used map[string]bool) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	maskBits := 32
	if ipnet.IP.To4() == nil {
		maskBits = 128
	}

	start := cloneIP(ipnet.IP)
	if rangeStart != "" {
		start = net.ParseIP(rangeStart)
		if start == nil {
			return "", fmt.Errorf("invalid range start %q", rangeStart)
		}
		if !ipnet.Contains(start) {
			return "", fmt.Errorf("range start %s is outside %s", rangeStart, cidr)
		}
	}
	var end net.IP
	if rangeEnd != "" {
		end = net.ParseIP(rangeEnd)
		if end == nil {
			return "", fmt.Errorf("invalid range end %q", rangeEnd)
		}
		if !ipnet.Contains(end) {
			return "", fmt.Errorf("range end %s is outside %s", rangeEnd, cidr)
		}
	}

	for cur := cloneIP(start); ipnet.Contains(cur); incIP(cur) {
		if end != nil && bytesAfter(cur, end) {
			break
		}
		if cur.Equal(ipnet.IP) { // network address
			continue
		}
		if !used[cur.String()] {
			return fmt.Sprintf("%s/%d", cur.String(), maskBits), nil
		}
	}
	return "", fmt.Errorf("no free address in %s (range %s-%s)", cidr, rangeStart, rangeEnd)
}

// bytesAfter reports whether a is strictly after b, comparing as unsigned
// big-endian integers (both normalized to the same length beforehand by
// net.IP's own To4()/16-byte representation).
func bytesAfter(a, b net.IP) bool {
	a, b = a.To16(), b.To16()
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
