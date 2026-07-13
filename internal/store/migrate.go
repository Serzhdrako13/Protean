package store

import (
	"context"
	"embed"
	"fmt"
	"sort"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies any embedded migration files not yet recorded in
// wgpanel.schema_migrations, in filename order. It's intentionally a
// hand-rolled runner rather than a migration library dependency: the
// panel's migration needs are small and static.
func Migrate(ctx context.Context, s *Store) error {
	pool := s.pool
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS wgpanel`); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS wgpanel.schema_migrations (
			filename    TEXT PRIMARY KEY,
			applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		var applied bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM wgpanel.schema_migrations WHERE filename = $1)`, name,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if applied {
			continue
		}

		sqlBytes, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO wgpanel.schema_migrations (filename) VALUES ($1)`, name,
		); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
