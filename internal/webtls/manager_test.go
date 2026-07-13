package webtls

import (
	"context"
	"fmt"
	"testing"
	"time"

	"protean/internal/store"
)

// fakeSealer is deliberately NOT identity -- it prefixes/strips a marker, so
// a test reading back through Get/Open without ever calling Seal would fail
// loudly instead of silently "working" on unencrypted data.
type fakeSealer struct{}

func (fakeSealer) Seal(plaintext string) ([]byte, error) {
	return []byte("SEALED:" + plaintext), nil
}
func (fakeSealer) Open(blob []byte) (string, error) {
	s := string(blob)
	const prefix = "SEALED:"
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return "", fmt.Errorf("not sealed: %q", s)
	}
	return s[len(prefix):], nil
}

type fakeStore struct {
	state     store.TLSState
	hasState  bool
	ss        store.TLSSelfSigned
	hasSS     bool
	acmeCache map[string][]byte
}

func newFakeStore() *fakeStore { return &fakeStore{acmeCache: map[string][]byte{}} }

func (f *fakeStore) GetTLSState(ctx context.Context) (store.TLSState, error) {
	if !f.hasState {
		return store.TLSState{
			Mode: "self_signed", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30,
			AcmeChallenge: "tls-alpn-01",
		}, nil
	}
	return f.state, nil
}
func (f *fakeStore) SetTLSState(ctx context.Context, t store.TLSState) error {
	f.state, f.hasState = t, true
	return nil
}
func (f *fakeStore) GetTLSSelfSigned(ctx context.Context) (store.TLSSelfSigned, bool, error) {
	return f.ss, f.hasSS, nil
}
func (f *fakeStore) SaveTLSSelfSignedCA(ctx context.Context, caCertPEM string, caKeyEnc []byte) error {
	f.ss.CACertPEM, f.ss.CAKeyEnc = caCertPEM, caKeyEnc
	f.hasSS = true
	return nil
}
func (f *fakeStore) SaveTLSSelfSignedLeaf(ctx context.Context, leafCertPEM string, leafKeyEnc []byte, issuedAt, expiresAt time.Time) error {
	f.ss.LeafCertPEM, f.ss.LeafKeyEnc, f.ss.IssuedAt, f.ss.ExpiresAt = leafCertPEM, leafKeyEnc, issuedAt, expiresAt
	return nil
}
func (f *fakeStore) AcmeCacheGet(ctx context.Context, key string) ([]byte, bool, error) {
	v, ok := f.acmeCache[key]
	return v, ok, nil
}
func (f *fakeStore) AcmeCachePut(ctx context.Context, key string, data []byte) error {
	f.acmeCache[key] = data
	return nil
}
func (f *fakeStore) AcmeCacheDelete(ctx context.Context, key string) error {
	delete(f.acmeCache, key)
	return nil
}

func TestManagerLoadBootstrapsSelfSignedOnFirstRun(t *testing.T) {
	m := New(newFakeStore(), fakeSealer{})
	ctx := context.Background()
	if err := m.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	cert, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a certificate, got nil")
	}
	status := m.GetStatus()
	if status.Mode != "self_signed" {
		t.Errorf("Mode = %q, want self_signed", status.Mode)
	}
	if status.Degraded {
		t.Errorf("expected not degraded on first boot, got LastError=%q", status.LastError)
	}
}

func TestManagerLoadReusesExistingCAAcrossRestarts(t *testing.T) {
	fs := newFakeStore()
	m1 := New(fs, fakeSealer{})
	if err := m1.Load(context.Background()); err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	ca1 := fs.ss.CACertPEM

	// Simulate a process restart: a fresh Manager over the same store.
	m2 := New(fs, fakeSealer{})
	if err := m2.Load(context.Background()); err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if fs.ss.CACertPEM != ca1 {
		t.Error("CA was regenerated across restarts -- it must be permanent")
	}
}

func TestLoadSkipsReissueWhenLeafFresh(t *testing.T) {
	fs := newFakeStore()
	m := New(fs, fakeSealer{})
	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	leaf1 := fs.ss.LeafCertPEM

	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if fs.ss.LeafCertPEM != leaf1 {
		t.Error("leaf was reissued even though it wasn't near expiry")
	}
}

func TestLoadReissuesWhenNearExpiry(t *testing.T) {
	fs := newFakeStore()
	fs.state = store.TLSState{
		Mode: "self_signed", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397,
		SSRenewBeforeDays: 500, // > validity -- always "near expiry"
	}
	fs.hasState = true
	m := New(fs, fakeSealer{})
	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	leaf1 := fs.ss.LeafCertPEM

	if err := m.Load(context.Background()); err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if fs.ss.LeafCertPEM == leaf1 {
		t.Error("leaf was NOT reissued even though renew_before_days exceeds validity")
	}
}

func TestManagerManualMode(t *testing.T) {
	fs := newFakeStore()
	m := New(fs, fakeSealer{})
	ctx := context.Background()
	if err := m.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}

	certPEM, keyPEM, _, err := IssueLeaf(fs.ss.CACertPEM, mustOpen(t, fs.ss.CAKeyEnc), ECDSAP256, "manual.example.com", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	keyEnc, _ := fakeSealer{}.Seal(keyPEM)

	err = m.Apply(ctx, store.TLSState{
		Mode: "manual", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30,
		ManualCertPEM: certPEM, ManualKeyEnc: keyEnc,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cert, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected manual certificate")
	}
	status := m.GetStatus()
	if status.LastServed != "manual" || status.Degraded {
		t.Errorf("status = %+v, want LastServed=manual, Degraded=false", status)
	}
}

func TestManagerManualModeExpiredFallsBackToSelfSigned(t *testing.T) {
	fs := newFakeStore()
	m := New(fs, fakeSealer{})
	ctx := context.Background()
	if err := m.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Issue an already-expired leaf (negative validity).
	certPEM, keyPEM, _, err := IssueLeaf(fs.ss.CACertPEM, mustOpen(t, fs.ss.CAKeyEnc), ECDSAP256, "manual.example.com", -time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	keyEnc, _ := fakeSealer{}.Seal(keyPEM)

	if err := m.Apply(ctx, store.TLSState{
		Mode: "manual", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30,
		ManualCertPEM: certPEM, ManualKeyEnc: keyEnc,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	cert, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected the self-signed fallback certificate, got nil")
	}
	status := m.GetStatus()
	if !status.Degraded || status.LastServed != "self_signed" {
		t.Errorf("status = %+v, want Degraded=true, LastServed=self_signed (fallback)", status)
	}
	if status.LastError == "" {
		t.Error("expected a non-empty LastError explaining the fallback")
	}
}

func TestManagerAcmeModeNoDomainsFallsBack(t *testing.T) {
	fs := newFakeStore()
	m := New(fs, fakeSealer{})
	ctx := context.Background()
	if err := m.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := m.Apply(ctx, store.TLSState{
		Mode: "acme", SSKeyAlgo: "ecdsa_p256", SSValidityDays: 397, SSRenewBeforeDays: 30,
		AcmeChallenge: "tls-alpn-01", // AcmeDomains deliberately empty
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	cert, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected the self-signed fallback certificate, got nil")
	}
	status := m.GetStatus()
	if !status.Degraded || status.LastServed != "self_signed" {
		t.Errorf("status = %+v, want degraded fallback to self_signed", status)
	}
}

func mustOpen(t *testing.T, blob []byte) string {
	t.Helper()
	s, err := (fakeSealer{}).Open(blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s
}

func TestDBCacheRoundTrip(t *testing.T) {
	fs := newFakeStore()
	c := &dbCache{store: fs, enc: fakeSealer{}}
	ctx := context.Background()

	if _, err := c.Get(ctx, "missing"); err == nil {
		t.Error("expected ErrCacheMiss-shaped error on missing key")
	}
	if err := c.Put(ctx, "k1", []byte("hello")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// The store should hold the SEALED form, never the plaintext.
	if string(fs.acmeCache["k1"]) == "hello" {
		t.Error("value stored unsealed")
	}
	got, err := c.Get(ctx, "k1")
	if err != nil || string(got) != "hello" {
		t.Errorf("Get = %q, %v, want \"hello\", nil", got, err)
	}
	if err := c.Delete(ctx, "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := fs.acmeCache["k1"]; ok {
		t.Error("key still present after Delete")
	}
}
