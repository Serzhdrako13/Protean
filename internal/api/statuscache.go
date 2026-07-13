package api

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"protean/internal/vpn"
)

// statusTTL / peersTTL bound how stale cached provider reads may be. The
// dashboard polls every ~7s and several views ask at once; caching for a few
// seconds collapses those into one SSH round-trip. singleflight collapses
// concurrent misses so a slow host is hit once, not N times.
const (
	statusTTL = 5 * time.Second
	peersTTL  = 5 * time.Second
)

type statusEntry struct {
	status  vpn.ServerStatus
	err     error
	expires time.Time
}

type peersEntry struct {
	peers   []vpn.Peer
	err     error
	expires time.Time
}

type statusCache struct {
	mu       sync.Mutex
	status   map[string]statusEntry
	peers    map[string]peersEntry
	sfStatus singleflight.Group
	sfPeers  singleflight.Group
	now      func() time.Time // injectable for tests
}

func newStatusCache() *statusCache {
	return &statusCache{
		status: make(map[string]statusEntry),
		peers:  make(map[string]peersEntry),
		now:    time.Now,
	}
}

// get returns a cached status if fresh, otherwise calls the provider (once,
// via singleflight) and caches the result (errors included, briefly, to avoid
// hammering a down host).
func (c *statusCache) get(ctx context.Context, prov vpn.Provider) (vpn.ServerStatus, error) {
	name := prov.Name()

	c.mu.Lock()
	if e, ok := c.status[name]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.status, e.err
	}
	c.mu.Unlock()

	v, _, _ := c.sfStatus.Do(name, func() (any, error) {
		// Re-check: a concurrent caller may have just filled the entry.
		c.mu.Lock()
		if e, ok := c.status[name]; ok && c.now().Before(e.expires) {
			c.mu.Unlock()
			return e, nil
		}
		c.mu.Unlock()

		status, err := prov.Status(ctx)
		e := statusEntry{status: status, err: err, expires: c.now().Add(statusTTL)}
		c.mu.Lock()
		c.status[name] = e
		c.mu.Unlock()
		return e, nil
	})
	e := v.(statusEntry)
	return e.status, e.err
}

// getPeers returns a provider's peer list via the short-TTL cache, collapsing
// concurrent misses with singleflight. Errors are cached briefly too.
func (c *statusCache) getPeers(ctx context.Context, prov vpn.Provider) ([]vpn.Peer, error) {
	name := prov.Name()

	c.mu.Lock()
	if e, ok := c.peers[name]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.peers, e.err
	}
	c.mu.Unlock()

	v, _, _ := c.sfPeers.Do(name, func() (any, error) {
		c.mu.Lock()
		if e, ok := c.peers[name]; ok && c.now().Before(e.expires) {
			c.mu.Unlock()
			return e, nil
		}
		c.mu.Unlock()

		peers, err := prov.ListPeers(ctx)
		e := peersEntry{peers: peers, err: err, expires: c.now().Add(peersTTL)}
		c.mu.Lock()
		c.peers[name] = e
		c.mu.Unlock()
		return e, nil
	})
	e := v.(peersEntry)
	return e.peers, e.err
}

// invalidate drops the cached status AND peers for a provider, e.g. right
// after a change that the operator should see reflected immediately.
func (c *statusCache) invalidate(name string) {
	c.mu.Lock()
	delete(c.status, name)
	delete(c.peers, name)
	c.mu.Unlock()
}
