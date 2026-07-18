package firewall

import "strings"

import "testing"

func TestRenderBaselineOrderingAndDefaultPolicy(t *testing.T) {
	out := Render(Policy{DefaultIncoming: "drop"},
		[]BaselinePort{
			{Proto: "udp", Port: 51820, Label: "WireGuard (wg0)"},
			{Proto: "tcp", Port: 22, Label: "SSH"},
		}, nil)

	if !strings.Contains(out, ":INPUT DROP [0:0]") {
		t.Errorf("missing DROP default policy:\n%s", out)
	}
	if !strings.Contains(out, "-A INPUT -i lo -j ACCEPT") {
		t.Errorf("missing loopback accept:\n%s", out)
	}
	if !strings.Contains(out, "-m state --state ESTABLISHED,RELATED -j ACCEPT") {
		t.Errorf("missing established/related accept:\n%s", out)
	}
	sshIdx := strings.Index(out, "--dport 22")
	wgIdx := strings.Index(out, "--dport 51820")
	if sshIdx == -1 || wgIdx == -1 {
		t.Fatalf("baseline ports missing:\n%s", out)
	}
	if sshIdx > wgIdx {
		t.Errorf("baseline should render sorted (tcp before udp): ssh at %d, wg at %d", sshIdx, wgIdx)
	}
	if !strings.Contains(out, `"protean-fw-baseline: SSH"`) {
		t.Errorf("baseline SSH row missing its label comment:\n%s", out)
	}
	if !strings.Contains(out, "COMMIT") {
		t.Errorf("missing COMMIT:\n%s", out)
	}
}

func TestRenderAcceptDefaultPolicy(t *testing.T) {
	out := Render(Policy{DefaultIncoming: "accept"}, nil, nil)
	if !strings.Contains(out, ":INPUT ACCEPT [0:0]") {
		t.Errorf("expected ACCEPT default policy:\n%s", out)
	}
}

func TestRenderCustomRuleSingleAndMultiport(t *testing.T) {
	out := Render(Policy{DefaultIncoming: "drop"}, nil, []Rule{
		{Action: "accept", Proto: "tcp", PortSpec: "443", Comment: "https"},
		{Action: "drop", Proto: "any", SourceCIDR: "203.0.113.0/24", Comment: "block"},
		{Action: "reject", Proto: "udp", PortSpec: "80,8080", Comment: "multi"},
	})
	if !strings.Contains(out, "-p tcp --dport 443 -j ACCEPT") {
		t.Errorf("single-port tcp rule wrong:\n%s", out)
	}
	if strings.Contains(out, "-p any") {
		t.Errorf(`"any" proto must be omitted, not literally rendered:\n%s`, out)
	}
	if !strings.Contains(out, "-A INPUT -s 203.0.113.0/24 -j DROP") {
		t.Errorf("any-proto source-only rule wrong:\n%s", out)
	}
	if !strings.Contains(out, "-p udp -m multiport --dports 80,8080 -j REJECT") {
		t.Errorf("multiport rule wrong:\n%s", out)
	}
	if !strings.Contains(out, `--comment "protean-fw: https"`) {
		t.Errorf("rule comment missing/wrong:\n%s", out)
	}
}

func TestRenderPortRangeUsesPlainDport(t *testing.T) {
	out := Render(Policy{DefaultIncoming: "drop"}, nil, []Rule{
		{Action: "accept", Proto: "tcp", PortSpec: "8000:8100"},
	})
	if !strings.Contains(out, "--dport 8000:8100") || strings.Contains(out, "multiport") {
		t.Errorf("port range should use plain --dport, not multiport:\n%s", out)
	}
}

func TestRenderCommentEscaping(t *testing.T) {
	out := Render(Policy{DefaultIncoming: "drop"}, nil, []Rule{
		{Action: "accept", Proto: "tcp", PortSpec: "1", Comment: `evil" -j ACCEPT #`},
	})
	// A literal quote in the admin's comment must never let them break out
	// of the --comment argument's own quoting.
	if strings.Contains(out, `evil" -j ACCEPT #`) {
		t.Errorf("comment quote was not escaped, rule injection possible:\n%s", out)
	}
}

func TestComputeBaselineSkipsUnknownPorts(t *testing.T) {
	baseline := ComputeBaseline(22, []InstancePort{
		{Label: "WireGuard (wg0)", Proto: "udp", Port: 51820},
		{Label: "Xray (unknown)", Proto: "tcp", Port: 0}, // not listening / unparsed yet
	}, false, nil)
	if len(baseline) != 2 {
		t.Fatalf("baseline = %+v, want SSH + wg0 only (zero-port instance skipped)", baseline)
	}
}

func TestComputeBaselinePanelHost(t *testing.T) {
	baseline := ComputeBaseline(22, nil, true, []int{8080, 443})
	if len(baseline) != 3 {
		t.Fatalf("baseline = %+v, want SSH + 2 panel ports", baseline)
	}
}

func TestComputeBaselineNoPanelPortsWhenNotPanelHost(t *testing.T) {
	baseline := ComputeBaseline(22, nil, false, []int{8080})
	if len(baseline) != 1 {
		t.Fatalf("baseline = %+v, want SSH only (not a panel host)", baseline)
	}
}

func TestDiffAddedRemoved(t *testing.T) {
	current := "*filter\n:INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n"
	proposed := "*filter\n:INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp --dport 443 -j ACCEPT\nCOMMIT\n"
	added, removed := Diff(current, proposed)
	if len(removed) != 0 {
		t.Errorf("removed = %v, want none", removed)
	}
	if len(added) != 1 || !strings.Contains(added[0], "443") {
		t.Errorf("added = %v, want one line mentioning 443", added)
	}
}
