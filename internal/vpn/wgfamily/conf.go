package wgfamily

import (
	"fmt"
	"strings"
)

// KV is an ordered key/value pair inside an [Interface] or [Peer] block.
type KV struct {
	Key   string
	Value string
}

// ConfPeer is one [Peer] block. Name comes from a "# Name: <name>" comment
// placed directly above the block — the panel's convention for storing a
// friendly label that wg itself has no concept of.
type ConfPeer struct {
	Name string
	Opts []KV
}

// ConfFile is a parsed wg-quick style config file ([Interface] + [Peer]*).
// Any comments other than the "# Name:" convention are dropped on
// round-trip: the panel owns this file once it starts managing peers
// through it.
type ConfFile struct {
	InterfaceOpts []KV
	Peers         []ConfPeer
}

// ParseConf parses wg-quick config file content.
func ParseConf(content string) *ConfFile {
	cf := &ConfFile{}
	section := ""
	var opts []KV
	name := ""
	nextName := ""

	flush := func() {
		switch section {
		case "interface":
			cf.InterfaceOpts = append(cf.InterfaceOpts, opts...)
		case "peer":
			cf.Peers = append(cf.Peers, ConfPeer{Name: name, Opts: opts})
		}
		opts = nil
	}

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if n, ok := strings.CutPrefix(line, "# Name:"); ok {
				nextName = strings.TrimSpace(n)
			}
			continue
		}
		if line == "[Interface]" {
			flush()
			section = "interface"
			name = ""
			continue
		}
		if line == "[Peer]" {
			flush()
			section = "peer"
			name = nextName
			nextName = ""
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		opts = append(opts, KV{Key: strings.TrimSpace(key), Value: strings.TrimSpace(value)})
	}
	flush()
	return cf
}

// Render produces wg-quick config text from the parsed structure.
func (cf *ConfFile) Render() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	for _, kv := range cf.InterfaceOpts {
		fmt.Fprintf(&b, "%s = %s\n", kv.Key, kv.Value)
	}
	for _, p := range cf.Peers {
		b.WriteString("\n")
		if p.Name != "" {
			// Defense in depth: a name is validated at the API layer, but
			// never let it inject extra lines into the config file.
			safeName := strings.ReplaceAll(strings.ReplaceAll(p.Name, "\n", " "), "\r", " ")
			fmt.Fprintf(&b, "# Name: %s\n", safeName)
		}
		b.WriteString("[Peer]\n")
		for _, kv := range p.Opts {
			fmt.Fprintf(&b, "%s = %s\n", kv.Key, kv.Value)
		}
	}
	return b.String()
}

// FirewallBackend selects how the panel-managed PostUp/PostDown rules are
// written: classic iptables (works everywhere via the iptables-nft shim on
// modern distros) or native nftables (for hosts without that shim).
type FirewallBackend int

const (
	BackendIptables FirewallBackend = iota
	BackendNft
)

// managedTag appears in every panel-managed PostUp/PostDown value, so all of
// them can be found and stripped regardless of backend.
const managedTag = "protean"

// HasManagedForwarding reports whether any panel-managed networking rules are
// present (forwarding is always part of the managed set when networking is on).
func (cf *ConfFile) HasManagedForwarding() bool {
	for _, kv := range cf.InterfaceOpts {
		if isManagedRule(kv) {
			return true
		}
	}
	return false
}

// HasManagedNAT reports whether panel-managed egress NAT is present.
func (cf *ConfFile) HasManagedNAT() bool {
	for _, kv := range cf.InterfaceOpts {
		if isManagedRule(kv) && strings.Contains(strings.ToLower(kv.Value), "masquerade") {
			return true
		}
	}
	return false
}

func isManagedRule(kv KV) bool {
	return (kv.Key == "PostUp" || kv.Key == "PostDown") && strings.Contains(kv.Value, managedTag)
}

// SetManagedNetworking rewrites the panel-managed PostUp/PostDown rules:
// forwarding (always, when enabled) plus optional egress NAT, using the given
// firewall backend. Idempotent; leaves any operator-written Post* lines alone.
func (cf *ConfFile) SetManagedNetworking(backend FirewallBackend, forwarding, egress bool, tunnelCIDR, wanIface string) {
	cf.dropManaged()
	if !forwarding {
		return
	}
	if backend == BackendNft {
		cf.InterfaceOpts = append(cf.InterfaceOpts, nftRules(egress, tunnelCIDR, wanIface)...)
	} else {
		cf.InterfaceOpts = append(cf.InterfaceOpts, iptablesRules(egress, tunnelCIDR, wanIface)...)
	}
}

// SetManagedForwarding is a convenience for iptables-only forwarding (kept for
// call sites that don't manage egress).
func (cf *ConfFile) SetManagedForwarding(enabled bool) {
	cf.SetManagedNetworking(BackendIptables, enabled, false, "", "")
}

func iptablesRules(egress bool, tunnelCIDR, wanIface string) []KV {
	const m = "protean-fwd"
	rules := []KV{
		{Key: "PostUp", Value: "iptables -I FORWARD -i %i -j ACCEPT -m comment --comment " + m},
		{Key: "PostUp", Value: "iptables -I FORWARD -o %i -j ACCEPT -m comment --comment " + m},
		{Key: "PostDown", Value: "iptables -D FORWARD -i %i -j ACCEPT -m comment --comment " + m},
		{Key: "PostDown", Value: "iptables -D FORWARD -o %i -j ACCEPT -m comment --comment " + m},
	}
	if egress && tunnelCIDR != "" && wanIface != "" {
		const n = "protean-nat"
		rules = append(rules,
			KV{Key: "PostUp", Value: fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE -m comment --comment %s", tunnelCIDR, wanIface, n)},
			KV{Key: "PostDown", Value: fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE -m comment --comment %s", tunnelCIDR, wanIface, n)},
		)
	}
	return rules
}

// nftRules uses a per-interface table `inet protean_%i` so teardown is a single
// `nft delete table` -- no fragile per-rule matching.
func nftRules(egress bool, tunnelCIDR, wanIface string) []KV {
	tbl := "inet protean_%i"
	up := []string{
		"nft add table " + tbl,
		fmt.Sprintf("nft add chain %s fwd '{ type filter hook forward priority filter; }'", tbl),
		fmt.Sprintf("nft add rule %s fwd iifname %%i accept", tbl),
		fmt.Sprintf("nft add rule %s fwd oifname %%i accept", tbl),
	}
	if egress && tunnelCIDR != "" && wanIface != "" {
		up = append(up,
			fmt.Sprintf("nft add chain %s nat '{ type nat hook postrouting priority srcnat; }'", tbl),
			fmt.Sprintf("nft add rule %s nat ip saddr %s oifname %s masquerade", tbl, tunnelCIDR, wanIface),
		)
	}
	rules := make([]KV, 0, len(up)+1)
	for _, u := range up {
		rules = append(rules, KV{Key: "PostUp", Value: u})
	}
	rules = append(rules, KV{Key: "PostDown", Value: "nft delete table " + tbl})
	return rules
}

func (cf *ConfFile) dropManaged() {
	kept := cf.InterfaceOpts[:0:0]
	for _, kv := range cf.InterfaceOpts {
		if isManagedRule(kv) {
			continue
		}
		kept = append(kept, kv)
	}
	cf.InterfaceOpts = kept
}

func (cf *ConfFile) InterfaceGet(key string) (string, bool) {
	return getOpt(cf.InterfaceOpts, key)
}

func (cf *ConfFile) InterfaceSet(key, value string) {
	cf.InterfaceOpts = setOpt(cf.InterfaceOpts, key, value)
}

// InterfaceUnset removes a key from the [Interface] section entirely (a
// no-op if it isn't set) -- e.g. clearing a custom MTU back to wg-quick's
// own default, which "MTU = 0" would not do (wg-quick rejects it).
func (cf *ConfFile) InterfaceUnset(key string) {
	kept := cf.InterfaceOpts[:0:0]
	for _, kv := range cf.InterfaceOpts {
		if strings.EqualFold(kv.Key, key) {
			continue
		}
		kept = append(kept, kv)
	}
	cf.InterfaceOpts = kept
}

// FindPeer returns a pointer into cf.Peers for the peer with the given
// public key, or nil if not found. The pointer is only valid until the next
// mutation of cf.Peers.
func (cf *ConfFile) FindPeer(publicKey string) *ConfPeer {
	for i := range cf.Peers {
		if pk, ok := getOpt(cf.Peers[i].Opts, "PublicKey"); ok && pk == publicKey {
			return &cf.Peers[i]
		}
	}
	return nil
}

func (cf *ConfFile) AddPeer(p ConfPeer) {
	cf.Peers = append(cf.Peers, p)
}

func (cf *ConfFile) RemovePeer(publicKey string) bool {
	for i, p := range cf.Peers {
		if pk, ok := getOpt(p.Opts, "PublicKey"); ok && pk == publicKey {
			cf.Peers = append(cf.Peers[:i], cf.Peers[i+1:]...)
			return true
		}
	}
	return false
}

func (cf *ConfFile) ReplacePeer(publicKey string, p ConfPeer) bool {
	for i := range cf.Peers {
		if pk, ok := getOpt(cf.Peers[i].Opts, "PublicKey"); ok && pk == publicKey {
			cf.Peers[i] = p
			return true
		}
	}
	return false
}

func getOpt(opts []KV, key string) (string, bool) {
	for _, kv := range opts {
		if strings.EqualFold(kv.Key, key) {
			return kv.Value, true
		}
	}
	return "", false
}

func setOpt(opts []KV, key, value string) []KV {
	for i, kv := range opts {
		if strings.EqualFold(kv.Key, key) {
			opts[i].Value = value
			return opts
		}
	}
	return append(opts, KV{Key: key, Value: value})
}
