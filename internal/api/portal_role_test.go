package api

import "testing"

func TestPortalRoleAllowed(t *testing.T) {
	allowed := []string{
		"/api/portal/me",
		"/api/portal/peers/wireguard/abc/config",
		"/api/account",
		"/api/account/2fa/setup",
		"/api/logout",
	}
	for _, p := range allowed {
		if !portalRoleAllowed(p) {
			t.Errorf("portalRoleAllowed(%q) = false, want true", p)
		}
	}

	denied := []string{
		"/api/servers",
		"/api/users",
		"/api/providers/wireguard",
		"/api/dashboard",
		"/",
	}
	for _, p := range denied {
		if portalRoleAllowed(p) {
			t.Errorf("portalRoleAllowed(%q) = true, want false", p)
		}
	}
}
