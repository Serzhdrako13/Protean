package auth

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"protean/internal/store"
)

// BruteForceStore is the persistence the guard needs (satisfied by
// *store.Store). Narrow and structural -- like every VPN provider's Store
// interface in this codebase -- so the escalation/window logic can be unit
// tested with a fake, without a real Postgres.
type BruteForceStore interface {
	GetLoginSecuritySettings(ctx context.Context) (store.LoginSecuritySettings, error)
	ListLoginIPRules(ctx context.Context) ([]store.LoginIPRule, error)
	RecordLoginAttempt(ctx context.Context, username, ip string, success bool, reason string) error
	CountRecentFailures(ctx context.Context, keyType, keyValue string, since time.Time) (int, error)
	GetLoginBanState(ctx context.Context, keyType, keyValue string) (store.LoginBanState, bool, error)
	UpsertLoginBanState(ctx context.Context, keyType, keyValue string, bannedUntil time.Time, escalationLevel int) error
}

// BruteForceGuard gates /api/login and /api/login/2fa: an admin-managed
// IP allow/deny list, then progressive bans keyed by username and/or IP
// (see migration 0026_login_security.sql for the full model). Replaces the
// old hardcoded in-memory LoginLimiter entirely.
type BruteForceGuard struct {
	store BruteForceStore
}

func NewBruteForceGuard(st BruteForceStore) *BruteForceGuard {
	return &BruteForceGuard{store: st}
}

// CheckResult is what CheckLogin decides before a password/TOTP check is
// even attempted.
type CheckResult struct {
	Allowed    bool
	Reason     string // "ip_denied" | "banned_ip" | "banned_username" | ""
	RetryAfter time.Duration
}

// CheckLogin decides whether a login attempt from ip (for username, if
// known yet) may proceed at all. Call this BEFORE checking the password;
// on Allowed==false, call LogRejected (not RecordResult -- a rejected
// attempt never touched real credentials, and must not feed the escalation
// counter, or every attempt made while already banned would keep
// extending the ban forever).
func (g *BruteForceGuard) CheckLogin(ctx context.Context, ip, username string) (CheckResult, error) {
	settings, err := g.store.GetLoginSecuritySettings(ctx)
	if err != nil {
		return CheckResult{}, fmt.Errorf("load settings: %w", err)
	}
	if !settings.Enabled {
		return CheckResult{Allowed: true}, nil
	}

	rules, err := g.store.ListLoginIPRules(ctx)
	if err != nil {
		return CheckResult{}, fmt.Errorf("load ip rules: %w", err)
	}
	switch matchIPRules(rules, ip) {
	case "deny":
		return CheckResult{Allowed: false, Reason: "ip_denied"}, nil
	case "allow":
		return CheckResult{Allowed: true}, nil
	}

	if settings.TrackByIP {
		if res, blocked, err := g.checkBan(ctx, "ip", ip); err != nil {
			return CheckResult{}, err
		} else if blocked {
			return res, nil
		}
	}
	if settings.TrackByUsername && username != "" {
		if res, blocked, err := g.checkBan(ctx, "username", username); err != nil {
			return CheckResult{}, err
		} else if blocked {
			return res, nil
		}
	}
	return CheckResult{Allowed: true}, nil
}

func (g *BruteForceGuard) checkBan(ctx context.Context, keyType, keyValue string) (CheckResult, bool, error) {
	ban, found, err := g.store.GetLoginBanState(ctx, keyType, keyValue)
	if err != nil {
		return CheckResult{}, false, err
	}
	if !found {
		return CheckResult{}, false, nil
	}
	remaining := time.Until(ban.BannedUntil)
	if remaining <= 0 {
		return CheckResult{}, false, nil
	}
	return CheckResult{Allowed: false, Reason: "banned_" + keyType, RetryAfter: remaining}, true, nil
}

// matchIPRules checks ip against the admin-managed list, deny taking
// precedence over allow when (implausibly) both would match. Rules may be
// a bare IP or a CIDR range.
func matchIPRules(rules []store.LoginIPRule, ip string) string {
	parsed := net.ParseIP(ip)
	matched := ""
	for _, r := range rules {
		if r.IPOrCIDR == ip {
			if r.Kind == "deny" {
				return "deny"
			}
			matched = "allow"
			continue
		}
		if parsed == nil {
			continue
		}
		if _, cidr, err := net.ParseCIDR(r.IPOrCIDR); err == nil && cidr.Contains(parsed) {
			if r.Kind == "deny" {
				return "deny"
			}
			matched = "allow"
		}
	}
	return matched
}

// LogRejected records an attempt that CheckLogin already turned away --
// logged for visibility/stats, but never touches escalation.
func (g *BruteForceGuard) LogRejected(ctx context.Context, ip, username, reason string) {
	_ = g.store.RecordLoginAttempt(ctx, username, ip, false, reason)
}

// RecordResult is called after a REAL credential check (password or TOTP
// code) -- success or failure. A failure counts toward the ban threshold;
// a success clears any standing escalation for both keys (a legitimate
// login is a strong signal the account/IP is not under attack right now).
func (g *BruteForceGuard) RecordResult(ctx context.Context, ip, username string, success bool, reason string) error {
	if err := g.store.RecordLoginAttempt(ctx, username, ip, success, reason); err != nil {
		return err
	}
	settings, err := g.store.GetLoginSecuritySettings(ctx)
	if err != nil {
		return err
	}
	if !settings.Enabled {
		return nil
	}

	if success {
		if settings.TrackByIP {
			_ = g.store.UpsertLoginBanState(ctx, "ip", ip, time.Now().Add(-time.Second), 0)
		}
		if settings.TrackByUsername && username != "" {
			_ = g.store.UpsertLoginBanState(ctx, "username", username, time.Now().Add(-time.Second), 0)
		}
		return nil
	}

	if settings.TrackByIP {
		if err := g.maybeEscalate(ctx, settings, "ip", ip); err != nil {
			return err
		}
	}
	if settings.TrackByUsername && username != "" {
		if err := g.maybeEscalate(ctx, settings, "username", username); err != nil {
			return err
		}
	}
	return nil
}

// maybeEscalate checks whether keyValue has now hit the failure threshold
// within the counting window, and if so issues (or escalates) a ban.
func (g *BruteForceGuard) maybeEscalate(ctx context.Context, settings store.LoginSecuritySettings, keyType, keyValue string) error {
	since := time.Now().Add(-time.Duration(settings.CountWindowMinutes) * time.Minute)
	count, err := g.store.CountRecentFailures(ctx, keyType, keyValue, since)
	if err != nil {
		return err
	}
	if count < settings.FailThreshold {
		return nil
	}

	level := 0
	if prev, found, err := g.store.GetLoginBanState(ctx, keyType, keyValue); err != nil {
		return err
	} else if found && time.Since(prev.BannedUntil) <= time.Duration(settings.EscalationResetMinutes)*time.Minute {
		level = prev.EscalationLevel + 1
	}

	minutes := float64(settings.BanBaseMinutes) * math.Pow(settings.EscalationFactor, float64(level))
	if minutes > float64(settings.MaxBanMinutes) {
		minutes = float64(settings.MaxBanMinutes)
	}
	duration := time.Duration(minutes * float64(time.Minute))
	return g.store.UpsertLoginBanState(ctx, keyType, keyValue, time.Now().Add(duration), level)
}

// RejectionMessage renders a CheckResult into a user-facing string in the
// given language ("en" or anything else -> Russian, matching
// internal/api's requestLang convention).
func RejectionMessage(res CheckResult, lang string) string {
	en := lang == "en"
	switch res.Reason {
	case "ip_denied":
		if en {
			return "access denied"
		}
		return "доступ запрещён"
	default:
		mins := int(math.Ceil(res.RetryAfter.Minutes()))
		if mins < 1 {
			mins = 1
		}
		if en {
			return fmt.Sprintf("too many failed attempts, try again in %d minute(s)", mins)
		}
		return fmt.Sprintf("слишком много неудачных попыток, повторите через %d мин.", mins)
	}
}
