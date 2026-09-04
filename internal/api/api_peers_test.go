package api

import (
	"strings"
	"testing"
)

// TestValidPeerName is the regression test for a real finding: a peer
// name flows unvalidated into places that render it literally into a
// generated config file -- most importantly ikev2/swanctl.go's `id =
// <CN>` line, which a newline in the name could use to inject arbitrary
// swanctl directives. Found live via an Opus-driven audit.
func TestValidPeerName(t *testing.T) {
	for _, ok := range []string{
		"router-1",
		"Office VPN",
		"Иван.Иванов_1",
		"user@example.com",
		"a",
	} {
		if !validPeerName.MatchString(ok) {
			t.Errorf("expected %q to be a valid peer name", ok)
		}
	}
	for _, bad := range []string{
		"",
		"name\nwith-newline",
		"name\r\nwith-crlf",
		"has/a/slash",
		"has;a;semicolon",
		"has$(a)subshell",
		"has`backticks`",
		strings.Repeat("a", 65), // over the 64-char cap despite otherwise-valid characters
	} {
		if validPeerName.MatchString(bad) {
			t.Errorf("expected %q to be rejected as an invalid peer name", bad)
		}
	}
}
