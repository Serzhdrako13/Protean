// Package wireguard implements the vpn.Provider interface for a stock
// WireGuard interface managed via wg/wg-quick.
package wireguard

import (
	"fmt"

	"protean/internal/vpn"
	"protean/internal/vpn/wgfamily"
)

// New builds a WireGuard provider for the given interface (e.g. "wg0"),
// backed by the given config file path on the host. instanceID is the unique
// registry/DB key (e.g. "wg0" single-server or "hq/wg0" multi-server); when
// empty it defaults to the interface name.
func New(ssh wgfamily.SSHRunner, instanceID, iface, confPath, publicHost string, backup wgfamily.BackupSink) vpn.Provider {
	return wgfamily.New(wgfamily.Options{
		ProviderName: "wireguard",
		InstanceID:   instanceID,
		Interface:    iface,
		ConfPath:     confPath,
		Binary:       "wg",
		ServiceName:  fmt.Sprintf("wg-quick@%s", iface),
		PublicHost:   publicHost,
		SSH:          ssh,
		Backup:       backup,
	})
}
