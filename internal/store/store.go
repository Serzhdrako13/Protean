// Package store wraps Postgres access for the panel. It uses pgx directly
// with hand-written SQL rather than an ORM -- the schema is small and
// stable enough that the extra dependency isn't worth it.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	// lockConn holds the dedicated connection owning the singleton advisory
	// lock for this process's lifetime (nil if not acquired).
	lockConn *pgxpool.Conn
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	if s.lockConn != nil {
		// Releasing the connection drops the session-level advisory lock.
		s.lockConn.Release()
		s.lockConn = nil
	}
	s.pool.Close()
}

// singletonLockKey is an arbitrary fixed key identifying "the Protean
// instance lock" within this database.
const singletonLockKey = 0x77_67_70_6e // "wgpn"

var ErrAlreadyRunning = errors.New("another Protean instance is already using this database")

// AcquireSingletonLock takes a session-level Postgres advisory lock on a
// dedicated connection, held until Close. It fails with ErrAlreadyRunning if
// another instance holds it -- the panel's in-process locking and rate
// limiter assume a single running instance, so starting a second one would
// reintroduce the config read-modify-write race.
func (s *Store) AcquireSingletonLock(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire lock connection: %w", err)
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(singletonLockKey)).Scan(&got); err != nil {
		conn.Release()
		return fmt.Errorf("advisory lock: %w", err)
	}
	if !got {
		conn.Release()
		return ErrAlreadyRunning
	}
	s.lockConn = conn
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}
