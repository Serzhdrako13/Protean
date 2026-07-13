package webtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"protean/internal/store"
)

// Store is the persistence Manager needs (satisfied by *store.Store).
// Narrow and structural (like every VPN provider's Store interface in this
// codebase) so tests can fake it without a real Postgres.
type Store interface {
	CacheStore
	GetTLSState(ctx context.Context) (store.TLSState, error)
	SetTLSState(ctx context.Context, t store.TLSState) error
	GetTLSSelfSigned(ctx context.Context) (store.TLSSelfSigned, bool, error)
	SaveTLSSelfSignedCA(ctx context.Context, caCertPEM string, caKeyEnc []byte) error
	SaveTLSSelfSignedLeaf(ctx context.Context, leafCertPEM string, leafKeyEnc []byte, issuedAt, expiresAt time.Time) error
}

// Status is the current TLS state surfaced to the admin UI/API.
type Status struct {
	Mode string

	SelfSignedExpiresAt time.Time

	// LastServed is which source actually produced the most recent
	// handshake's certificate ("self_signed", "acme", "manual") -- can
	// differ from Mode when the configured mode is failing and the
	// permanent self-signed fallback stepped in.
	LastServed string
	// LastError is the most recent apply/renew/serve failure, if any
	// (e.g. ACME renewal failed, manual cert expired) -- empty when
	// everything is healthy. Surfaced as an admin-facing warning banner.
	LastError string
	// Degraded is true when LastServed != Mode -- the configured method
	// isn't actually working right now.
	Degraded bool
}

// Manager owns the panel's own web-listener certificate: it always keeps a
// self-signed cert ready (generated once, renewed forever) as a permanent
// fallback, and additionally drives whichever mode is configured
// (self_signed/acme/manual/proxy). Safe for concurrent use; GetCertificate
// is called concurrently by the TLS stack.
type Manager struct {
	store Store
	enc   Sealer

	mu         sync.RWMutex
	state      store.TLSState
	caCertPEM  string
	caKeyPEM   string
	selfSigned *tls.Certificate
	ssExpires  time.Time
	acmeMgr    *autocert.Manager
	manualCert *tls.Certificate

	lastServed atomic.Value // string
	lastErr    atomic.Value // string
}

func New(st Store, enc Sealer) *Manager {
	m := &Manager{store: st, enc: enc}
	m.lastServed.Store("")
	m.lastErr.Store("")
	return m
}

// Load bootstraps the manager at startup: ensures the self-signed CA and a
// valid leaf exist (generating them on first-ever run), loads the
// configured mode, and wires ACME/manual if applicable. Must be called
// once before Load's caller starts serving TLS.
func (m *Manager) Load(ctx context.Context) error {
	state, err := m.store.GetTLSState(ctx)
	if err != nil {
		return fmt.Errorf("load tls state: %w", err)
	}
	if err := m.ensureSelfSigned(ctx, state); err != nil {
		return fmt.Errorf("bootstrap self-signed cert: %w", err)
	}
	return m.apply(ctx, state)
}

// ensureSelfSigned generates the CA (once ever) and a leaf (issuing or
// re-issuing as needed) -- this runs regardless of the active mode, since
// self-signed is the permanent fallback, not just the default mode.
func (m *Manager) ensureSelfSigned(ctx context.Context, state store.TLSState) error {
	ss, found, err := m.store.GetTLSSelfSigned(ctx)
	if err != nil {
		return err
	}
	if !found {
		caCertPEM, caKeyPEM, err := GenerateCA()
		if err != nil {
			return err
		}
		caKeyEnc, err := m.enc.Seal(caKeyPEM)
		if err != nil {
			return err
		}
		if err := m.store.SaveTLSSelfSignedCA(ctx, caCertPEM, caKeyEnc); err != nil {
			return err
		}
		ss = store.TLSSelfSigned{CACertPEM: caCertPEM, CAKeyEnc: caKeyEnc}
	}
	caKeyPEM, err := m.enc.Open(ss.CAKeyEnc)
	if err != nil {
		return fmt.Errorf("decrypt CA key: %w", err)
	}

	m.mu.Lock()
	m.caCertPEM, m.caKeyPEM = ss.CACertPEM, caKeyPEM
	m.mu.Unlock()

	needsIssue := ss.LeafCertPEM == "" || time.Until(ss.ExpiresAt) < time.Duration(state.SSRenewBeforeDays)*24*time.Hour
	if !needsIssue {
		return m.loadLeafInto(ctx, ss)
	}
	return m.reissueSelfSigned(ctx, state)
}

func (m *Manager) loadLeafInto(ctx context.Context, ss store.TLSSelfSigned) error {
	leafKeyPEM, err := m.enc.Open(ss.LeafKeyEnc)
	if err != nil {
		return fmt.Errorf("decrypt leaf key: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(ss.LeafCertPEM), []byte(leafKeyPEM))
	if err != nil {
		return fmt.Errorf("load leaf keypair: %w", err)
	}
	m.mu.Lock()
	m.selfSigned = &cert
	m.ssExpires = ss.ExpiresAt
	m.mu.Unlock()
	return nil
}

// reissueSelfSigned issues a fresh leaf under the existing CA and persists
// it -- called both at bootstrap (missing/expiring leaf) and by the
// background renew loop.
func (m *Manager) reissueSelfSigned(ctx context.Context, state store.TLSState) error {
	m.mu.RLock()
	caCertPEM, caKeyPEM := m.caCertPEM, m.caKeyPEM
	m.mu.RUnlock()

	validFor := time.Duration(state.SSValidityDays) * 24 * time.Hour
	if validFor <= 0 {
		validFor = 397 * 24 * time.Hour
	}
	leafCertPEM, leafKeyPEM, expires, err := IssueLeaf(caCertPEM, caKeyPEM, KeyAlgo(state.SSKeyAlgo), state.SSSans, validFor)
	if err != nil {
		return err
	}
	leafKeyEnc, err := m.enc.Seal(leafKeyPEM)
	if err != nil {
		return err
	}
	if err := m.store.SaveTLSSelfSignedLeaf(ctx, leafCertPEM, leafKeyEnc, time.Now(), expires); err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(leafCertPEM), []byte(leafKeyPEM))
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.selfSigned = &cert
	m.ssExpires = expires
	m.mu.Unlock()
	return nil
}

// ReissueSelfSigned forces a fresh self-signed leaf under the existing
// (permanent) CA using the currently persisted settings -- an explicit
// admin action, e.g. right after changing SANs/key algo/validity, instead
// of waiting for RunRenewLoop's next tick.
func (m *Manager) ReissueSelfSigned(ctx context.Context) error {
	m.mu.RLock()
	state := m.state
	m.mu.RUnlock()
	return m.reissueSelfSigned(ctx, state)
}

// Apply persists a new configuration and reconfigures the manager to match
// -- called from the API when an admin changes TLS settings. Self-signed
// re-issuance (key algo/validity/SANs changed) always happens inline here
// since it's cheap and local; ACME issuance happens lazily on the next
// handshake/renewal (it needs a real challenge round-trip, not something to
// block an API response on).
func (m *Manager) Apply(ctx context.Context, state store.TLSState) error {
	if err := m.store.SetTLSState(ctx, state); err != nil {
		return err
	}
	if err := m.reissueSelfSigned(ctx, state); err != nil {
		// Self-signed is the fallback for everything else -- if even this
		// fails, surface it immediately rather than silently continuing.
		return fmt.Errorf("reissue self-signed cert: %w", err)
	}
	return m.apply(ctx, state)
}

// apply wires up mode-specific state (ACME manager / manual cert) from an
// already-persisted state, without touching the self-signed cert.
func (m *Manager) apply(ctx context.Context, state store.TLSState) error {
	var acmeMgr *autocert.Manager
	var manualCert *tls.Certificate

	switch state.Mode {
	case "acme":
		mgr, err := m.buildACMEManager(state)
		if err != nil {
			m.setLastErr(fmt.Sprintf("acme config: %v", err))
		} else {
			acmeMgr = mgr
		}
	case "manual":
		if state.ManualCertPEM != "" && len(state.ManualKeyEnc) > 0 {
			keyPEM, err := m.enc.Open(state.ManualKeyEnc)
			if err != nil {
				m.setLastErr(fmt.Sprintf("decrypt manual key: %v", err))
			} else if cert, err := tls.X509KeyPair([]byte(state.ManualCertPEM), []byte(keyPEM)); err != nil {
				m.setLastErr(fmt.Sprintf("parse manual cert: %v", err))
			} else {
				manualCert = &cert
			}
		}
	}

	m.mu.Lock()
	m.state = state
	m.acmeMgr = acmeMgr
	m.manualCert = manualCert
	m.mu.Unlock()
	return nil
}

// TODO(untested-live): this ACME path is unit-tested (config validation,
// fallback-to-self-signed on failure) but has never completed a real
// issuance round-trip against an actual CA -- doing so needs a public
// domain with DNS pointed at this host and port 80 (HTTP-01) or 443
// (TLS-ALPN-01) reachable from the internet, none of which exist in a dev
// sandbox. Before relying on this in production, do one manual live test
// (Let's Encrypt STAGING first -- acme_directory_url =
// https://acme-staging-v02.api.letsencrypt.org/directory -- to avoid
// burning the real CA's rate limits while debugging) and only then switch
// to the production directory URL. See docs/OPERATIONS.md §3 and
// docs/DEVELOPER-GUIDE.md §26 for the same note.
func (m *Manager) buildACMEManager(state store.TLSState) (*autocert.Manager, error) {
	domains := splitSANs(state.AcmeDomains)
	if state.AcmeDomains == "" || len(domains) == 0 {
		return nil, fmt.Errorf("no domains configured")
	}
	client := &acme.Client{}
	if state.AcmeDirectoryURL != "" {
		client.DirectoryURL = state.AcmeDirectoryURL
	}
	if state.AcmeTrustRootPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(state.AcmeTrustRootPEM)) {
			return nil, fmt.Errorf("invalid trust root PEM")
		}
		client.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	}
	return &autocert.Manager{
		Cache:      &dbCache{store: m.store, enc: m.enc},
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Email:      state.AcmeEmail,
		Client:     client,
	}, nil
}

// HTTPHandler exposes the ACME HTTP-01 responder when that challenge type
// is selected -- callers (main.go) mount this on a plain port-80 listener
// only in that case; TLS-ALPN-01 (the default) needs no separate port at
// all, it's handled inside GetCertificate during the TLS handshake itself.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	m.mu.RLock()
	acmeMgr, challenge := m.acmeMgr, m.state.AcmeChallenge
	m.mu.RUnlock()
	if acmeMgr == nil || challenge != "http-01" {
		return fallback
	}
	return acmeMgr.HTTPHandler(fallback)
}

// GetCertificate is the tls.Config hook: serves the configured mode's
// certificate, falling back to the permanent self-signed one on any
// failure (unconfigured ACME, failed renewal, expired/invalid manual
// cert) -- this is what keeps the connection on HTTPS (and Secure cookies
// working) even when the "real" certificate is broken, instead of ever
// needing to drop to plain HTTP. See webtls package doc and the TLS admin
// page's status banner for how LastServed/LastError surface this.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	mode := m.state.Mode
	acmeMgr := m.acmeMgr
	manual := m.manualCert
	fallback := m.selfSigned
	m.mu.RUnlock()

	switch mode {
	case "acme":
		if acmeMgr != nil {
			cert, err := acmeMgr.GetCertificate(hello)
			if err == nil {
				m.recordServed("acme", "")
				return cert, nil
			}
			m.recordServed("self_signed", "acme: "+err.Error())
		} else {
			m.recordServed("self_signed", "acme: not configured")
		}
	case "manual":
		if manual != nil && !leafExpired(manual) {
			m.recordServed("manual", "")
			return manual, nil
		}
		m.recordServed("self_signed", "manual certificate missing or expired")
	default:
		m.recordServed("self_signed", "")
	}

	if fallback == nil {
		return nil, fmt.Errorf("no TLS certificate available yet")
	}
	return fallback, nil
}

func leafExpired(cert *tls.Certificate) bool {
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return true
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return true
		}
		cert.Leaf = parsed
	}
	return time.Now().After(cert.Leaf.NotAfter)
}

func (m *Manager) recordServed(source, errMsg string) {
	m.lastServed.Store(source)
	m.lastErr.Store(errMsg)
	if errMsg != "" {
		slog.Warn("webtls: falling back to self-signed certificate", "reason", errMsg)
	}
}

func (m *Manager) setLastErr(msg string) {
	m.lastErr.Store(msg)
	slog.Warn("webtls: configuration problem", "error", msg)
}

// GetStatus reports the current state for the admin UI.
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	mode := m.state.Mode
	expires := m.ssExpires
	m.mu.RUnlock()
	served, _ := m.lastServed.Load().(string)
	errMsg, _ := m.lastErr.Load().(string)
	return Status{
		Mode: mode, SelfSignedExpiresAt: expires,
		LastServed: served, LastError: errMsg,
		Degraded: served != "" && served != mode,
	}
}

// RunRenewLoop periodically re-issues the self-signed leaf as it
// approaches expiry -- runs until ctx is cancelled. The active mode's own
// certificate (ACME via autocert, manual via admin re-upload) has its own
// renewal path; this loop only ever touches the self-signed fallback, so
// it must keep running regardless of which mode is currently active.
func (m *Manager) RunRenewLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.RLock()
			state := m.state
			expires := m.ssExpires
			m.mu.RUnlock()
			if time.Until(expires) > time.Duration(state.SSRenewBeforeDays)*24*time.Hour {
				continue
			}
			if err := m.reissueSelfSigned(ctx, state); err != nil {
				slog.Error("webtls: self-signed renewal failed", "error", err)
			} else {
				slog.Info("webtls: self-signed certificate renewed")
			}
		}
	}
}
