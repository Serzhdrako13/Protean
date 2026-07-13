package xray

import (
	"encoding/json"
	"fmt"
)

// Outbound is an Xray outbound object.
type Outbound = map[string]any

// FreedomOutbound sends traffic straight to the internet (direct egress).
func FreedomOutbound() Outbound {
	return Outbound{"protocol": "freedom", "tag": "direct"}
}

// BlackholeOutbound drops traffic (used as a default deny for blocked routes).
func BlackholeOutbound() Outbound {
	return Outbound{"protocol": "blackhole", "tag": "blocked"}
}

// BuildServerConfig assembles a full Xray server config: the chosen inbound(s)
// plus egress. When relays is empty, traffic egresses directly (freedom). When
// relays is set (foreign egress relay chain), all traffic is routed out
// through hop 0, which dials hop 1, which dials hop 2, and so on -- an N-hop
// chain: client -> this server -> relay0 -> relay1 -> ... -> internet.
func BuildServerConfig(inbounds []map[string]any, relays []Outbound) ([]byte, error) {
	if len(inbounds) == 0 {
		return nil, fmt.Errorf("no inbounds")
	}
	outbounds := []any{}
	routing := map[string]any{}
	if len(relays) > 0 {
		for i, hop := range relays {
			hop["tag"] = fmt.Sprintf("relay%d", i)
			if i < len(relays)-1 {
				// Chain this hop's outbound through the next one (Xray-core's
				// native outbound-chaining field) instead of dialing the
				// internet directly.
				setDialerProxy(hop, fmt.Sprintf("relay%d", i+1))
			}
			outbounds = append(outbounds, hop)
		}
		outbounds = append(outbounds, FreedomOutbound(), BlackholeOutbound())
		// Send everything through the first hop; direct only as an explicit
		// fallback is intentionally NOT added (egress must go abroad).
		routing = map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "relay0"},
			},
		}
	} else {
		outbounds = append(outbounds, FreedomOutbound(), BlackholeOutbound())
	}

	ins := make([]any, len(inbounds))
	for i, in := range inbounds {
		ins[i] = in
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  ins,
		"outbounds": outbounds,
	}
	if len(routing) > 0 {
		cfg["routing"] = routing
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// RelaySpec describes the foreign relay this server should egress through: the
// relay's public host + the strategy and its client parameters (as issued by
// the relay's own panel). It is turned into an Xray outbound.
type RelaySpec struct {
	Strategy string // one of the registered strategy names
	Host     string
	Params   Params
}

// BuildRelayOutbound turns a RelaySpec into an Xray outbound dialing the relay.
// Supports the dial-able strategies (VLESS+Reality, VLESS/Trojan over TLS,
// Shadowsocks). Returns an error for strategies that can't act as an egress
// dialer here.
func BuildRelayOutbound(spec RelaySpec) (Outbound, error) {
	p := spec.Params
	port := portOf(p, "443")
	switch spec.Strategy {
	case "reality-vless-tcp":
		return vlessOutbound(spec.Host, port, p[pUUID], "xtls-rprx-vision", map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"serverName":  p.get(pSNI, ""),
				"publicKey":   p.get(pRealityPub, ""),
				"shortId":     p.get(pShortID, ""),
				"fingerprint": "chrome",
			},
		}), nil
	case "vless-vision-tls":
		return vlessOutbound(spec.Host, port, p[pUUID], "xtls-rprx-vision", map[string]any{
			"network":     "tcp",
			"security":    "tls",
			"tlsSettings": map[string]any{"serverName": p.get(pDomain, spec.Host)},
		}), nil
	case "vless-grpc-tls":
		return vlessOutbound(spec.Host, port, p[pUUID], "", map[string]any{
			"network":      "grpc",
			"security":     "tls",
			"grpcSettings": map[string]any{"serviceName": p.get(pGRPCService, "grpc")},
			"tlsSettings":  map[string]any{"serverName": p.get(pDomain, spec.Host)},
		}), nil
	case "trojan-tcp-tls":
		return Outbound{
			"protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": spec.Host, "port": port, "password": p[pPassword],
			}}},
			"streamSettings": map[string]any{
				"network":     "tcp",
				"security":    "tls",
				"tlsSettings": map[string]any{"serverName": p.get(pDomain, spec.Host)},
			},
		}, nil
	case "shadowsocks-2022":
		return Outbound{
			"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": spec.Host, "port": port,
				"method": p.get(pSSMethod, "2022-blake3-aes-128-gcm"), "password": p[pPassword],
			}}},
		}, nil
	default:
		return nil, fmt.Errorf("strategy %q cannot be used as an egress relay", spec.Strategy)
	}
}

// setDialerProxy points an outbound's dialer through another outbound (by
// tag) instead of the network directly -- Xray-core's native mechanism for
// chaining outbounds into a relay-through-relay path.
func setDialerProxy(o Outbound, tag string) {
	ss, _ := o["streamSettings"].(map[string]any)
	if ss == nil {
		ss = map[string]any{}
	}
	ss["sockopt"] = map[string]any{"dialerProxy": tag}
	o["streamSettings"] = ss
}

func vlessOutbound(host string, port int, uuid, flow string, stream map[string]any) Outbound {
	user := map[string]any{"id": uuid, "encryption": "none"}
	if flow != "" {
		user["flow"] = flow
	}
	return Outbound{
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": host, "port": port, "users": []any{user},
		}}},
		"streamSettings": stream,
	}
}
