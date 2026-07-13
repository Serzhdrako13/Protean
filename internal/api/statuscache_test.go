package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"protean/internal/vpn"
)

type countingProvider struct {
	name      string
	calls     int32
	peerCalls int32
}

func (c *countingProvider) Name() string { return c.name }
func (c *countingProvider) Type() string { return c.name }
func (c *countingProvider) Status(context.Context) (vpn.ServerStatus, error) {
	atomic.AddInt32(&c.calls, 1)
	return vpn.ServerStatus{Provider: c.name, Up: true}, nil
}
func (c *countingProvider) ListPeers(context.Context) ([]vpn.Peer, error) {
	atomic.AddInt32(&c.peerCalls, 1)
	return nil, nil
}
func (c *countingProvider) AddPeer(context.Context, vpn.PeerSpec) (vpn.NewPeerResult, error) {
	return vpn.NewPeerResult{}, vpn.ErrNotImplemented
}
func (c *countingProvider) UpdatePeer(context.Context, string, vpn.PeerSpec) error {
	return vpn.ErrNotImplemented
}
func (c *countingProvider) RemovePeer(context.Context, string) error { return vpn.ErrNotImplemented }
func (c *countingProvider) UpdateServerConfig(context.Context, vpn.ServerConfig) error {
	return vpn.ErrNotImplemented
}

func TestStatusCacheHitsAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newStatusCache()
	c.now = func() time.Time { return now }

	p := &countingProvider{name: "wireguard"}

	// First call hits the provider; the next few within TTL are cached.
	for i := 0; i < 4; i++ {
		if _, err := c.get(context.Background(), p); err != nil {
			t.Fatalf("get: %v", err)
		}
	}
	if got := atomic.LoadInt32(&p.calls); got != 1 {
		t.Fatalf("expected 1 provider call within TTL, got %d", got)
	}

	// After TTL, it refreshes.
	now = now.Add(statusTTL + time.Second)
	if _, err := c.get(context.Background(), p); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := atomic.LoadInt32(&p.calls); got != 2 {
		t.Fatalf("expected refresh after TTL, got %d calls", got)
	}
}

func TestPeersCacheAndInvalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newStatusCache()
	c.now = func() time.Time { return now }
	p := &countingProvider{name: "wireguard"}

	for i := 0; i < 4; i++ {
		if _, err := c.getPeers(context.Background(), p); err != nil {
			t.Fatalf("getPeers: %v", err)
		}
	}
	if got := atomic.LoadInt32(&p.peerCalls); got != 1 {
		t.Fatalf("expected 1 ListPeers within TTL, got %d", got)
	}

	// invalidate must drop the peers cache too.
	c.invalidate("wireguard")
	if _, err := c.getPeers(context.Background(), p); err != nil {
		t.Fatalf("getPeers: %v", err)
	}
	if got := atomic.LoadInt32(&p.peerCalls); got != 2 {
		t.Fatalf("invalidate should refresh peers; got %d", got)
	}
}

func TestPeersCacheSingleFlight(t *testing.T) {
	c := newStatusCache()
	// Freeze time so entries never expire during the test.
	c.now = func() time.Time { return time.Unix(1000, 0) }
	p := &blockingProvider{start: make(chan struct{})}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.getPeers(context.Background(), p)
		}()
	}
	close(p.start) // release all goroutines roughly together
	wg.Wait()

	if got := atomic.LoadInt32(&p.peerCalls); got > 1 {
		t.Fatalf("singleflight should collapse concurrent misses to 1, got %d", got)
	}
}

// blockingProvider blocks ListPeers until start is closed, so concurrent
// callers pile up on the same singleflight key.
type blockingProvider struct {
	countingProvider
	start chan struct{}
}

func (b *blockingProvider) ListPeers(context.Context) ([]vpn.Peer, error) {
	<-b.start
	atomic.AddInt32(&b.peerCalls, 1)
	return nil, nil
}

func TestStatusCacheInvalidate(t *testing.T) {
	now := time.Unix(1000, 0)
	c := newStatusCache()
	c.now = func() time.Time { return now }
	p := &countingProvider{name: "wireguard"}

	_, _ = c.get(context.Background(), p)
	c.invalidate("wireguard")
	_, _ = c.get(context.Background(), p)

	if got := atomic.LoadInt32(&p.calls); got != 2 {
		t.Fatalf("invalidate should force a refresh; got %d calls", got)
	}
}
