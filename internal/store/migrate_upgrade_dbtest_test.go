//go:build dbtest

package store

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrateUpgradeFromEarlySchema simulates upgrading a real,
// already-populated OLD install: only the first handful of migrations are
// applied by hand (matching what an early deployment actually has on
// disk), real data is inserted against that early schema, then the
// CURRENT Migrate() runs on top. Every other dbtest here starts from an
// empty schema (TestMigrateIdempotent included) -- this is the one that
// actually proves the upgrade path, not just "works on a fresh install".
func TestMigrateUpgradeFromEarlySchema(t *testing.T) {
	url := os.Getenv("PROTEAN_TEST_DB")
	if url == "" {
		t.Skip("PROTEAN_TEST_DB not set; skipping DB integration tests")
	}
	ctx := context.Background()

	raw, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(ctx, `DROP SCHEMA IF EXISTS protean CASCADE`); err != nil {
		t.Fatalf("drop schema: %v", err)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	const cutoff = 5
	if len(names) < cutoff {
		t.Fatalf("expected at least %d embedded migrations, got %d", cutoff, len(names))
	}

	if _, err := raw.Exec(ctx, `CREATE SCHEMA protean`); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := raw.Exec(ctx, `
		CREATE TABLE protean.schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, name := range names[:cutoff] {
		sqlBytes, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := raw.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply early migration %s: %v", name, err)
		}
		if _, err := raw.Exec(ctx, `INSERT INTO protean.schema_migrations (filename) VALUES ($1)`, name); err != nil {
			t.Fatalf("record early migration %s: %v", name, err)
		}
	}

	// Real data against the early schema (just the columns 0001_init.sql
	// actually created) -- must survive the upgrade untouched.
	if _, err := raw.Exec(ctx, `INSERT INTO protean.users (username, password_hash) VALUES ('old-admin', 'hash')`); err != nil {
		t.Fatalf("seed pre-existing user: %v", err)
	}

	// The actual upgrade: open + Migrate through the normal path an
	// already-deployed panel binary would use on startup.
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := Migrate(ctx, s); err != nil {
		t.Fatalf("Migrate (upgrade from early schema): %v", err)
	}

	rows, err := raw.Query(ctx, `SELECT filename FROM protean.schema_migrations`)
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	got := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[name] = true
	}
	rows.Close()
	for _, name := range names {
		if !got[name] {
			t.Errorf("migration %s not recorded after upgrade", name)
		}
	}

	var survived int
	if err := raw.QueryRow(ctx, `SELECT count(*) FROM protean.users WHERE username = 'old-admin'`).Scan(&survived); err != nil {
		t.Fatalf("check pre-existing user survived: %v", err)
	}
	if survived != 1 {
		t.Errorf("pre-existing user did not survive the upgrade: count = %d", survived)
	}

	if err := Migrate(ctx, s); err != nil {
		t.Fatalf("second Migrate (must be a no-op): %v", err)
	}
}
