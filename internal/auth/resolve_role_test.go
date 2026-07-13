package auth

import (
	"testing"

	"protean/internal/store"
)

func TestResolveRoleFromRules(t *testing.T) {
	rules := []store.AuthGroupRule{
		{Method: "ldap", Role: "admin", GroupValue: "cn=vpn-admins,ou=groups,dc=example,dc=com"},
		{Method: "ldap", Role: "user", GroupValue: "cn=vpn-users,ou=groups,dc=example,dc=com"},
	}

	t.Run("admin match", func(t *testing.T) {
		role, ok := resolveRoleFromRules(rules, []string{"cn=vpn-admins,ou=groups,dc=example,dc=com"})
		if !ok || role != "admin" {
			t.Fatalf("got role=%q ok=%v, want admin/true", role, ok)
		}
	})

	t.Run("user match", func(t *testing.T) {
		role, ok := resolveRoleFromRules(rules, []string{"cn=vpn-users,ou=groups,dc=example,dc=com"})
		if !ok || role != "user" {
			t.Fatalf("got role=%q ok=%v, want user/true", role, ok)
		}
	})

	t.Run("no match denies", func(t *testing.T) {
		role, ok := resolveRoleFromRules(rules, []string{"cn=someone-else,ou=groups,dc=example,dc=com"})
		if ok {
			t.Fatalf("expected no match, got role=%q", role)
		}
	})

	t.Run("empty groups denies", func(t *testing.T) {
		_, ok := resolveRoleFromRules(rules, nil)
		if ok {
			t.Fatal("expected no match for empty groups")
		}
	})

	t.Run("both matched admin wins", func(t *testing.T) {
		role, ok := resolveRoleFromRules(rules, []string{
			"cn=vpn-admins,ou=groups,dc=example,dc=com",
			"cn=vpn-users,ou=groups,dc=example,dc=com",
		})
		if !ok || role != "admin" {
			t.Fatalf("got role=%q ok=%v, want admin/true", role, ok)
		}
	})
}
