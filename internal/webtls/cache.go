package webtls

import (
	"context"

	"golang.org/x/crypto/acme/autocert"
)

// Sealer encrypts/decrypts secret material at rest (satisfied by
// *auth.Encryptor) -- same convention as every VPN provider package.
type Sealer interface {
	Seal(plaintext string) ([]byte, error)
	Open(blob []byte) (string, error)
}

// CacheStore is the persistence dbCache needs (satisfied by *store.Store).
type CacheStore interface {
	AcmeCacheGet(ctx context.Context, key string) ([]byte, bool, error)
	AcmeCachePut(ctx context.Context, key string, data []byte) error
	AcmeCacheDelete(ctx context.Context, key string) error
}

// dbCache implements autocert.Cache over the panel's own DB instead of the
// library's default on-disk directory -- this app never persists secrets to
// the filesystem (distroless container, no writable/persistent local path
// convention); every other secret in this schema already goes through
// Seal/Open into a DB column, so the ACME account key + issued cert/key
// blobs autocert wants to cache follow the same rule.
type dbCache struct {
	store CacheStore
	enc   Sealer
}

var _ autocert.Cache = (*dbCache)(nil)

func (c *dbCache) Get(ctx context.Context, key string) ([]byte, error) {
	blob, ok, err := c.store.AcmeCacheGet(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, autocert.ErrCacheMiss
	}
	plain, err := c.enc.Open(blob)
	if err != nil {
		return nil, err
	}
	return []byte(plain), nil
}

func (c *dbCache) Put(ctx context.Context, key string, data []byte) error {
	blob, err := c.enc.Seal(string(data))
	if err != nil {
		return err
	}
	return c.store.AcmeCachePut(ctx, key, blob)
}

func (c *dbCache) Delete(ctx context.Context, key string) error {
	return c.store.AcmeCacheDelete(ctx, key)
}
