package auth

import (
	"context"
	"testing"
	"time"

	"protean/internal/store"
)

// fakeBFStore is a minimal in-memory BruteForceStore -- CountRecentFailures
// is a prescribed value the test sets directly (the real sliding-window
// COUNT query is exercised separately, for real, in store_integration_test.go
// under -tags dbtest); this keeps these tests focused purely on the guard's
// escalation math and control flow.
type fakeBFStore struct {
	settings   store.LoginSecuritySettings
	rules      []store.LoginIPRule
	bans       map[string]store.LoginBanState // key: keyType+"/"+keyValue
	failCounts map[string]int                 // key: keyType+"/"+keyValue
	attempts   []store.LoginAttemptRow
}

func newFakeBFStore() *fakeBFStore {
	return &fakeBFStore{
		settings: store.LoginSecuritySettings{
			Enabled: true, TrackByUsername: true, TrackByIP: true,
			FailThreshold: 3, CountWindowMinutes: 5,
			BanBaseMinutes: 5, EscalationFactor: 2, EscalationResetMinutes: 60,
			MaxBanMinutes: 1440,
		},
		bans:       map[string]store.LoginBanState{},
		failCounts: map[string]int{},
	}
}

func bfKey(keyType, keyValue string) string { return keyType + "/" + keyValue }

func (f *fakeBFStore) GetLoginSecuritySettings(context.Context) (store.LoginSecuritySettings, error) {
	return f.settings, nil
}
func (f *fakeBFStore) ListLoginIPRules(context.Context) ([]store.LoginIPRule, error) {
	return f.rules, nil
}
func (f *fakeBFStore) RecordLoginAttempt(_ context.Context, username, ip string, success bool, reason string) error {
	f.attempts = append(f.attempts, store.LoginAttemptRow{Username: username, IP: ip, Success: success, Reason: reason})
	return nil
}
func (f *fakeBFStore) CountRecentFailures(_ context.Context, keyType, keyValue string, _ time.Time) (int, error) {
	return f.failCounts[bfKey(keyType, keyValue)], nil
}
func (f *fakeBFStore) GetLoginBanState(_ context.Context, keyType, keyValue string) (store.LoginBanState, bool, error) {
	b, ok := f.bans[bfKey(keyType, keyValue)]
	return b, ok, nil
}
func (f *fakeBFStore) UpsertLoginBanState(_ context.Context, keyType, keyValue string, bannedUntil time.Time, level int) error {
	f.bans[bfKey(keyType, keyValue)] = store.LoginBanState{
		KeyType: keyType, KeyValue: keyValue, BannedUntil: bannedUntil, EscalationLevel: level,
	}
	return nil
}

func TestCheckLoginAllowedByDefault(t *testing.T) {
	fs := newFakeBFStore()
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "1.2.3.4", "alice")
	if err != nil || !res.Allowed {
		t.Fatalf("CheckLogin = %+v, err=%v, want Allowed=true", res, err)
	}
}

func TestCheckLoginDenyListBlocks(t *testing.T) {
	fs := newFakeBFStore()
	fs.rules = []store.LoginIPRule{{IPOrCIDR: "1.2.3.4", Kind: "deny"}}
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "1.2.3.4", "alice")
	if err != nil || res.Allowed || res.Reason != "ip_denied" {
		t.Fatalf("CheckLogin = %+v, err=%v, want Allowed=false Reason=ip_denied", res, err)
	}
}

func TestCheckLoginDenyListCIDRMatch(t *testing.T) {
	fs := newFakeBFStore()
	fs.rules = []store.LoginIPRule{{IPOrCIDR: "10.0.0.0/24", Kind: "deny"}}
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "10.0.0.55", "alice")
	if err != nil || res.Allowed {
		t.Fatalf("CheckLogin = %+v, err=%v, want denied via CIDR match", res, err)
	}
}

func TestCheckLoginAllowListBypassesBan(t *testing.T) {
	fs := newFakeBFStore()
	fs.rules = []store.LoginIPRule{{IPOrCIDR: "1.2.3.4", Kind: "allow"}}
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4", BannedUntil: time.Now().Add(time.Hour),
	}
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "1.2.3.4", "alice")
	if err != nil || !res.Allowed {
		t.Fatalf("CheckLogin = %+v, err=%v, want Allowed=true (allow-listed, bypasses ban)", res, err)
	}
}

func TestCheckLoginActiveBanBlocks(t *testing.T) {
	fs := newFakeBFStore()
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4", BannedUntil: time.Now().Add(3 * time.Minute),
	}
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "1.2.3.4", "alice")
	if err != nil || res.Allowed || res.Reason != "banned_ip" {
		t.Fatalf("CheckLogin = %+v, err=%v, want Allowed=false Reason=banned_ip", res, err)
	}
	if res.RetryAfter <= 0 || res.RetryAfter > 3*time.Minute {
		t.Errorf("RetryAfter = %v, want ~3m", res.RetryAfter)
	}
}

func TestCheckLoginExpiredBanAllows(t *testing.T) {
	fs := newFakeBFStore()
	fs.bans[bfKey("username", "alice")] = store.LoginBanState{
		KeyType: "username", KeyValue: "alice", BannedUntil: time.Now().Add(-time.Minute),
	}
	g := NewBruteForceGuard(fs)
	res, err := g.CheckLogin(context.Background(), "1.2.3.4", "alice")
	if err != nil || !res.Allowed {
		t.Fatalf("CheckLogin = %+v, err=%v, want Allowed=true (ban expired)", res, err)
	}
}

func TestRecordResultTriggersBanAtThreshold(t *testing.T) {
	fs := newFakeBFStore()
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 3 // just hit the default threshold
	fs.failCounts[bfKey("username", "alice")] = 3
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "alice", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	ban, ok := fs.bans[bfKey("ip", "1.2.3.4")]
	if !ok {
		t.Fatal("expected a ban to be issued for the IP")
	}
	wantDuration := 5 * time.Minute
	gotDuration := time.Until(ban.BannedUntil)
	if gotDuration < wantDuration-time.Second || gotDuration > wantDuration+time.Second {
		t.Errorf("ban duration = %v, want ~%v", gotDuration, wantDuration)
	}
	if ban.EscalationLevel != 0 {
		t.Errorf("escalation level = %d, want 0 (first ban)", ban.EscalationLevel)
	}
	// Username tracked too (both enabled by default).
	if _, ok := fs.bans[bfKey("username", "alice")]; !ok {
		t.Error("expected a ban to be issued for the username too")
	}
}

func TestRecordResultBelowThresholdNoBan(t *testing.T) {
	fs := newFakeBFStore()
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 2 // below default threshold of 3
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "alice", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	if _, ok := fs.bans[bfKey("ip", "1.2.3.4")]; ok {
		t.Error("no ban should be issued below threshold")
	}
}

func TestRecordResultEscalatesWithinResetWindow(t *testing.T) {
	fs := newFakeBFStore()
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 3
	fs.failCounts[bfKey("username", "alice")] = 0 // only IP re-offends this time
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4",
		BannedUntil:     time.Now().Add(-30 * time.Second), // expired recently, within the 60min reset window
		EscalationLevel: 0,
	}
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "alice", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	ban := fs.bans[bfKey("ip", "1.2.3.4")]
	if ban.EscalationLevel != 1 {
		t.Fatalf("escalation level = %d, want 1", ban.EscalationLevel)
	}
	wantDuration := 10 * time.Minute // base(5) * factor(2)^1
	gotDuration := time.Until(ban.BannedUntil)
	if gotDuration < wantDuration-time.Second || gotDuration > wantDuration+time.Second {
		t.Errorf("escalated ban duration = %v, want ~%v", gotDuration, wantDuration)
	}
}

func TestRecordResultResetsAfterLongGap(t *testing.T) {
	fs := newFakeBFStore()
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 3
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4",
		BannedUntil:     time.Now().Add(-2 * time.Hour), // long past the 60min reset window
		EscalationLevel: 3,
	}
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	ban := fs.bans[bfKey("ip", "1.2.3.4")]
	if ban.EscalationLevel != 0 {
		t.Fatalf("escalation level = %d, want 0 (reset after long gap)", ban.EscalationLevel)
	}
	wantDuration := 5 * time.Minute
	gotDuration := time.Until(ban.BannedUntil)
	if gotDuration < wantDuration-time.Second || gotDuration > wantDuration+time.Second {
		t.Errorf("ban duration = %v, want ~%v (base, not escalated)", gotDuration, wantDuration)
	}
}

func TestRecordResultCapsAtMaxBan(t *testing.T) {
	fs := newFakeBFStore()
	fs.settings.MaxBanMinutes = 12 // lower than base(5)*factor(2)^1=10... push to level 2 (20min) to exceed cap
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 3
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4",
		BannedUntil: time.Now().Add(-time.Second), EscalationLevel: 1, // -> next level 2, 5*2^2=20min, capped to 12
	}
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	ban := fs.bans[bfKey("ip", "1.2.3.4")]
	wantDuration := 12 * time.Minute
	gotDuration := time.Until(ban.BannedUntil)
	if gotDuration < wantDuration-time.Second || gotDuration > wantDuration+time.Second {
		t.Errorf("capped ban duration = %v, want ~%v", gotDuration, wantDuration)
	}
}

func TestRecordResultSuccessClearsBan(t *testing.T) {
	fs := newFakeBFStore()
	fs.bans[bfKey("ip", "1.2.3.4")] = store.LoginBanState{
		KeyType: "ip", KeyValue: "1.2.3.4", BannedUntil: time.Now().Add(10 * time.Minute), EscalationLevel: 2,
	}
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "alice", true, ""); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	ban := fs.bans[bfKey("ip", "1.2.3.4")]
	if !ban.BannedUntil.Before(time.Now()) || ban.EscalationLevel != 0 {
		t.Errorf("ban state after success = %+v, want cleared (past BannedUntil, level 0)", ban)
	}
}

func TestRecordResultDisabledIsNoop(t *testing.T) {
	fs := newFakeBFStore()
	fs.settings.Enabled = false
	fs.failCounts[bfKey("ip", "1.2.3.4")] = 99
	g := NewBruteForceGuard(fs)
	if err := g.RecordResult(context.Background(), "1.2.3.4", "alice", false, "bad_password"); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	if _, ok := fs.bans[bfKey("ip", "1.2.3.4")]; ok {
		t.Error("guard disabled -- no ban should ever be issued")
	}
}
