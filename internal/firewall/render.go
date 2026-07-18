// Package firewall renders a server's INPUT-chain firewall ruleset as
// iptables-restore-format text, and computes/diffs against it. Pure and
// deterministic by design -- this is the primary unit-tested surface of
// the firewall feature; the actual "what's this server's baseline"
// live-host/DB gathering lives in internal/api, which calls ComputeBaseline
// with already-fetched inputs.
package firewall

import (
	"fmt"
	"sort"
	"strings"
)

// commentPrefix tags every rule this feature writes, disjoint from
// cmd_forward's "protean-mesh" and wg-quick's PostUp/PostDown lines, so
// they never collide.
const commentPrefix = "protean-fw"

// BaselinePort is a "never lock this out" port -- computed fresh at every
// apply from live DB/host state (see ComputeBaseline), never persisted.
type BaselinePort struct {
	Proto string // "tcp" | "udp"
	Port  int
	Label string // e.g. "SSH", "WireGuard (wg0)", "Panel (web)"
}

// Rule is one of the admin's own custom rules (store.FirewallRule, decoupled
// from the store package so this stays a leaf/pure package).
type Rule struct {
	Action     string // "accept" | "drop" | "reject"
	Proto      string // "tcp" | "udp" | "any"
	PortSpec   string // "443" | "8000:8100" | "80,443" | "" (any port)
	SourceCIDR string // "" = anywhere
	Comment    string
}

// Policy is the server-level default for anything not matched above.
type Policy struct {
	DefaultIncoming string // "drop" | "accept"
}

// Render produces the full *filter table text for iptables-restore: chain
// policies, then loopback + established/related, then the locked baseline
// ports, then the admin's own rules in the order given, then COMMIT.
// FORWARD/OUTPUT are always ACCEPT -- this feature manages INPUT only (see
// the design's explicit v1 ceiling).
func Render(policy Policy, baseline []BaselinePort, rules []Rule) string {
	def := "DROP"
	if strings.EqualFold(policy.DefaultIncoming, "accept") {
		def = "ACCEPT"
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("*filter")
	w(":INPUT %s [0:0]", def)
	w(":FORWARD ACCEPT [0:0]")
	w(":OUTPUT ACCEPT [0:0]")
	w("-A INPUT -i lo -j ACCEPT")
	w("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")

	// Baseline rows sorted for a deterministic, diff-friendly rendering --
	// caller assembly order (DB iteration) isn't guaranteed stable.
	sorted := append([]BaselinePort(nil), baseline...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Proto != sorted[j].Proto {
			return sorted[i].Proto < sorted[j].Proto
		}
		return sorted[i].Port < sorted[j].Port
	})
	for _, bp := range sorted {
		w(`-A INPUT -p %s --dport %d -j ACCEPT -m comment --comment "%s-baseline: %s"`,
			bp.Proto, bp.Port, commentPrefix, escapeComment(bp.Label))
	}

	for _, r := range rules {
		w("%s", renderRule(r))
	}

	w("COMMIT")
	return b.String()
}

func renderRule(r Rule) string {
	var parts []string
	parts = append(parts, "-A INPUT")
	if r.Proto != "" && r.Proto != "any" {
		parts = append(parts, "-p", r.Proto)
	}
	if r.PortSpec != "" {
		if strings.Contains(r.PortSpec, ",") {
			parts = append(parts, "-m", "multiport", "--dports", r.PortSpec)
		} else {
			parts = append(parts, "--dport", r.PortSpec)
		}
	}
	if r.SourceCIDR != "" {
		parts = append(parts, "-s", r.SourceCIDR)
	}
	parts = append(parts, "-j", strings.ToUpper(r.Action))
	comment := commentPrefix
	if r.Comment != "" {
		comment = commentPrefix + ": " + escapeComment(r.Comment)
	}
	parts = append(parts, "-m", "comment", "--comment", `"`+comment+`"`)
	return strings.Join(parts, " ")
}

// escapeComment strips characters iptables' comment match can't carry
// (quotes would break the -m comment --comment "..." shape above).
func escapeComment(s string) string {
	return strings.ReplaceAll(s, `"`, "")
}

// Diff produces a simple added/removed line summary between the current
// live ruleset (iptables-save output) and a newly rendered one, for the
// dry-run preview. This is informational only -- the real safety
// mechanism is `iptables-restore --test` plus the armed rollback timer,
// not the quality of this diff, so a plain line-set comparison (not a full
// sequence/LCS diff) is enough.
func Diff(current, proposed string) (added, removed []string) {
	curLines := lineSet(current)
	newLines := lineSet(proposed)
	for _, l := range splitNonEmpty(proposed) {
		if !curLines[l] {
			added = append(added, l)
		}
	}
	for _, l := range splitNonEmpty(current) {
		if !newLines[l] {
			removed = append(removed, l)
		}
	}
	return added, removed
}

func lineSet(text string) map[string]bool {
	m := map[string]bool{}
	for _, l := range splitNonEmpty(text) {
		m[l] = true
	}
	return m
}

func splitNonEmpty(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
