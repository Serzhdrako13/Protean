package vpn

import (
	"fmt"
	"net"
)

// CIDROverlap reports whether two CIDRs share any address. Two networks
// overlap iff one contains the other's base address.
func CIDROverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// CheckNoOverlap verifies that candidate does not overlap any CIDR in
// existing. It's how the mesh keeps its address space unambiguous: without
// NAT, two overlapping networks would give the hub two routes for the same
// destination and traffic would go to the wrong site.
func CheckNoOverlap(candidate string, existing []string) error {
	_, candNet, err := net.ParseCIDR(candidate)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", candidate, err)
	}
	for _, e := range existing {
		_, exNet, err := net.ParseCIDR(e)
		if err != nil {
			continue // ignore malformed existing entries; not our job to reject them here
		}
		if CIDROverlap(candNet, exNet) {
			return fmt.Errorf("%s overlaps existing %s", candidate, e)
		}
	}
	return nil
}
