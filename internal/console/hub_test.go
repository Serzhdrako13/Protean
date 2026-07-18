package console

import (
	"errors"
	"testing"
	"time"
)

func TestHubMintConsumeSingleUse(t *testing.T) {
	h := NewHub(Config{})
	tok, err := h.Mint("alice", "srv1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	user, target, err := h.Consume(tok)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if user != "alice" || target != "srv1" {
		t.Fatalf("Consume = (%q, %q), want (alice, srv1)", user, target)
	}
	if _, _, err := h.Consume(tok); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("second Consume err = %v, want ErrTicketInvalid", err)
	}
}

func TestHubConsumeUnknownTicket(t *testing.T) {
	h := NewHub(Config{})
	if _, _, err := h.Consume("does-not-exist"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("err = %v, want ErrTicketInvalid", err)
	}
}

func TestHubTicketExpiry(t *testing.T) {
	h := NewHub(Config{TicketTTL: 10 * time.Millisecond})
	tok, err := h.Mint("alice", "srv1")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, _, err := h.Consume(tok); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("err = %v, want ErrTicketInvalid", err)
	}
}

func TestHubAcquirePerUserCap(t *testing.T) {
	h := NewHub(Config{MaxPerUser: 1})
	release1, err := h.Acquire("alice")
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := h.Acquire("alice"); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("second Acquire err = %v, want ErrTooManySessions", err)
	}
	// A different user isn't affected by alice's cap.
	release2, err := h.Acquire("bob")
	if err != nil {
		t.Fatalf("Acquire for bob: %v", err)
	}
	release1()
	// Releasing frees alice's slot back up.
	release3, err := h.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	release2()
	release3()
}

func TestHubAcquireTotalCap(t *testing.T) {
	h := NewHub(Config{MaxTotal: 1})
	release, err := h.Acquire("alice")
	if err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	if _, err := h.Acquire("bob"); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("Acquire for bob err = %v, want ErrTooManySessions (global cap)", err)
	}
	release()
	if release2, err := h.Acquire("bob"); err != nil {
		t.Fatalf("Acquire after release: %v", err)
	} else {
		release2()
	}
}

func TestHubAcquireReleaseIdempotent(t *testing.T) {
	h := NewHub(Config{MaxPerUser: 1})
	release, err := h.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	release()
	release() // must not double-decrement past zero
	if _, err := h.Acquire("alice"); err != nil {
		t.Fatalf("Acquire after idempotent release: %v", err)
	}
}

func TestHubMintReflectsAcquireCapacity(t *testing.T) {
	// Mint's advisory check should see the same counters Acquire uses --
	// a session already holding a slot via Acquire makes a subsequent Mint
	// for that user fail fast, before a WS upgrade is even attempted.
	h := NewHub(Config{MaxPerUser: 1})
	release, err := h.Acquire("alice")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if _, err := h.Mint("alice", "srv1"); !errors.Is(err, ErrTooManySessions) {
		t.Fatalf("Mint err = %v, want ErrTooManySessions", err)
	}
	release()
	if _, err := h.Mint("alice", "srv1"); err != nil {
		t.Fatalf("Mint after release: %v", err)
	}
}
