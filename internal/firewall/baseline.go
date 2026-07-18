package firewall

// InstancePort is a single VPN instance's listening port, as gathered by
// the caller (internal/api, from the live provider's Status()/Current())
// -- decoupled from any specific provider type so this package doesn't
// need to import internal/vpn/*.
type InstancePort struct {
	Label string // e.g. "WireGuard (wg0)"
	Proto string // "tcp" | "udp"
	Port  int
}

// ComputeBaseline assembles the "never lock these out" port list: the SSH
// port always, every VPN instance's real listening port, and the panel's
// own web port(s) when this server is flagged as the panel host (see
// store.Server.PanelHost).
func ComputeBaseline(sshPort int, instances []InstancePort, panelHost bool, panelPorts []int) []BaselinePort {
	out := []BaselinePort{{Proto: "tcp", Port: sshPort, Label: "SSH"}}
	for _, ip := range instances {
		if ip.Port <= 0 {
			continue // not listening / port unknown yet -- nothing to protect
		}
		out = append(out, BaselinePort{Proto: ip.Proto, Port: ip.Port, Label: ip.Label})
	}
	if panelHost {
		for _, p := range panelPorts {
			if p <= 0 {
				continue
			}
			out = append(out, BaselinePort{Proto: "tcp", Port: p, Label: "Panel (web)"})
		}
	}
	return out
}
