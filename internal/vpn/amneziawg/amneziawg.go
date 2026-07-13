// Package amneziawg implements the vpn.Provider interface for AmneziaWG, a
// WireGuard fork with DPI-obfuscation parameters (Jc/Jmin/Jmax/S1/S2/H1-4).
// It shares its wire format and CLI shape with WireGuard almost entirely
// (awg/awg-quick mirror wg/wg-quick), so it reuses wgfamily rather than
// reimplementing the same logic.
package amneziawg

import (
	"fmt"

	"protean/internal/vpn"
	"protean/internal/vpn/wgfamily"
)

// ObfuscationKeys are the extra [Interface]/[Peer] fields AmneziaWG adds on
// top of stock WireGuard. Server-side ones (Jc, Jmin, Jmax, S1, S2, H1-4) go
// through ServerConfig.Extra; peers don't carry extra obfuscation fields of
// their own today.
var ObfuscationKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"}

// New builds an AmneziaWG provider for the given interface (e.g. "awg0"),
// backed by the given config file path on the host. instanceID is the unique
// registry/DB key; when empty it defaults to the interface name.
func New(ssh wgfamily.SSHRunner, instanceID, iface, confPath, publicHost string, backup wgfamily.BackupSink) vpn.Provider {
	return wgfamily.New(wgfamily.Options{
		ProviderName: "amneziawg",
		InstanceID:   instanceID,
		Interface:    iface,
		ConfPath:     confPath,
		Binary:       "awg",
		ServiceName:  fmt.Sprintf("awg-quick@%s", iface),
		PublicHost:   publicHost,
		SSH:          ssh,
		Backup:       backup,
	})
}
