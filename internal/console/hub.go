// Package console implements the web-based interactive SSH console: a
// WebSocket<->SSH-PTY bridge (Bridge) plus session bookkeeping (Hub) --
// short-lived WS-auth tickets and the concurrency caps. See
// docs/OPERATIONS.md for the operator-facing picture and the design
// rationale recorded in this session's memory for why a WS upgrade needs
// its own ticket-based auth instead of trusting the session cookie alone.
package console

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Config holds the operator-tunable console limits, wired from env vars in
// internal/config (CONSOLE_IDLE_TIMEOUT, CONSOLE_MAX_SESSION,
// CONSOLE_MAX_PER_USER, CONSOLE_MAX_TOTAL). Zero disables the
// corresponding limit.
type Config struct {
	IdleTimeout time.Duration
	MaxSession  time.Duration
	MaxPerUser  int
	MaxTotal    int
	// TicketTTL defaults to 30s if zero -- long enough for the SPA to open
	// the WS right after minting, short enough that a leaked/logged ticket
	// is useless within moments.
	TicketTTL time.Duration
}

var (
	ErrTicketInvalid   = errors.New("console: invalid or expired ticket")
	ErrTooManySessions = errors.New("console: too many concurrent console sessions")
)

type ticket struct {
	username string
	target   string
	expires  time.Time
	used     bool
}

// Hub tracks short-lived, single-use WS-auth tickets and live-session
// concurrency counts. A WS upgrade isn't subject to the browser's CORS/
// preflight protections a normal fetch gets, so it authenticates via an
// opaque ticket minted by an already-authenticated, CSRF-checked REST call
// (POST /api/console/sessions) instead of trusting the session cookie
// alone at the upgrade -- see internal/api's console handlers.
type Hub struct {
	cfg Config

	mu      sync.Mutex
	tickets map[string]*ticket
	byUser  map[string]int
	total   int
}

// IdleTimeout and MaxSession expose the configured lifecycle limits for
// constructing a Bridge -- the Hub is the one place both the ticket/cap
// config and these values live.
func (h *Hub) IdleTimeout() time.Duration { return h.cfg.IdleTimeout }
func (h *Hub) MaxSession() time.Duration  { return h.cfg.MaxSession }

func NewHub(cfg Config) *Hub {
	if cfg.TicketTTL == 0 {
		cfg.TicketTTL = 30 * time.Second
	}
	return &Hub{
		cfg:     cfg,
		tickets: map[string]*ticket{},
		byUser:  map[string]int{},
	}
}

// Mint issues a new single-use ticket for username to open a console to
// target, after an advisory capacity check (fast, friendly 429 before the
// client even attempts the WS upgrade). This check is NOT a reservation --
// a minted ticket might never be redeemed (browser closed before
// connecting), so the authoritative cap enforcement happens in Acquire,
// when a session actually starts. Checking twice is simpler and just as
// effective as reserving-then-releasing a slot across an unbounded
// "might never connect" window.
func (h *Hub) Mint(username, target string) (string, error) {
	h.mu.Lock()
	if err := h.checkCapacityLocked(username); err != nil {
		h.mu.Unlock()
		return "", err
	}
	h.sweepLocked()
	h.mu.Unlock()

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)

	h.mu.Lock()
	h.tickets[tok] = &ticket{username: username, target: target, expires: time.Now().Add(h.cfg.TicketTTL)}
	h.mu.Unlock()
	return tok, nil
}

// Consume validates and single-use-consumes a ticket, returning the
// username/target it was minted for.
func (h *Hub) Consume(tok string) (username, target string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked()
	t, ok := h.tickets[tok]
	if !ok || t.used || time.Now().After(t.expires) {
		return "", "", ErrTicketInvalid
	}
	t.used = true
	delete(h.tickets, tok) // single-use: gone the instant it's redeemed
	return t.username, t.target, nil
}

func (h *Hub) sweepLocked() {
	now := time.Now()
	for k, t := range h.tickets {
		if now.After(t.expires) {
			delete(h.tickets, k)
		}
	}
}

func (h *Hub) checkCapacityLocked(username string) error {
	if h.cfg.MaxPerUser > 0 && h.byUser[username] >= h.cfg.MaxPerUser {
		return ErrTooManySessions
	}
	if h.cfg.MaxTotal > 0 && h.total >= h.cfg.MaxTotal {
		return ErrTooManySessions
	}
	return nil
}

// Acquire enforces the per-user/global concurrency caps for a session that
// is actually starting (after ticket redemption, right before opening the
// shell). The returned release func must be called exactly once when the
// session ends; it's safe to call from a deferred/duplicate teardown path
// (idempotent).
func (h *Hub) Acquire(username string) (release func(), err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.checkCapacityLocked(username); err != nil {
		return nil, err
	}
	h.byUser[username]++
	h.total++
	var once sync.Once
	release = func() {
		once.Do(func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.byUser[username]--
			if h.byUser[username] <= 0 {
				delete(h.byUser, username)
			}
			h.total--
		})
	}
	return release, nil
}
