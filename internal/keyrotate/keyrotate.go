// Package keyrotate re-encrypts every AES-256-GCM-sealed secret in the
// database from an old SECRET_KEY to a new one. Every secret the panel
// stores at rest goes through exactly one *auth.Encryptor (constructed once
// from SECRET_KEY at startup, see cmd/panel/main.go) shared by every
// package that needs to seal/open something -- there is no per-secret key
// or key version stored anywhere, so changing the key means physically
// rewriting every sealed row, not just updating an env var.
//
// A partially-rotated database -- some rows readable only by the old key,
// others only by the new one -- is worse than not rotating at all: no
// single Encryptor can read the whole database anymore. Rotate guards
// against that by doing every rewrite inside one Postgres transaction
// (all-or-nothing commit) and by verifying every rewritten row actually
// opens with the new key, with the original plaintext recovered exactly,
// before that transaction commits.
package keyrotate

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"protean/internal/auth"
)

// sealedColumn describes one column that holds an AES-256-GCM blob produced
// by *auth.Encryptor.Seal.
type sealedColumn struct {
	table   string
	column  string
	keyCols []string // primary key column(s) addressing each row
}

// sealedColumns is the exhaustive list of every sealed column in the schema,
// found by tracing every *auth.Encryptor Seal/Open call site (directly, and
// via each package-local Sealer interface: internal/vpn/openvpn,
// internal/vpn/xray, internal/vpn/ikev2, internal/webtls) back to the
// migration that created its column. TestSealedColumnsMatchSchema
// (keyrotate_dbtest_test.go) queries information_schema for every bytea
// column in the schema and fails if one isn't registered here -- the
// safety net against a future sealed secret silently escaping rotation.
var sealedColumns = []sealedColumn{
	{"peer_secrets", "encrypted_private_key", []string{"provider", "public_key"}},
	{"ca_material", "enc_key_pem", []string{"provider"}},
	{"openvpn_clients", "enc_key_pem", []string{"cn"}},
	{"ikev2_clients", "enc_key_pem", []string{"cn"}},
	{"notify_channels", "config", []string{"kind"}},
	{"servers", "enc_key_pem", []string{"id"}},
	{"xray_instances", "enc_params", []string{"provider"}},
	{"xray_instances", "enc_relay", []string{"provider"}},
	{"xray_clients", "enc_cred", []string{"provider", "name"}},
	{"tls_state", "manual_key_enc", []string{"id"}},
	{"acme_cache", "value", []string{"key"}},
	{"tls_self_signed", "ca_key_enc", []string{"id"}},
	{"tls_self_signed", "leaf_key_enc", []string{"id"}},
	{"ldap_settings", "enc_bind_password", []string{"id"}},
	{"oidc_settings", "enc_client_secret", []string{"id"}},
}

// minSealedBlobLen is the smallest possible output of Encryptor.Seal (12
// byte nonce + 16 byte GCM tag, empty plaintext). Several columns default
// to an empty ” blob rather than NULL when unset (ldap_settings,
// oidc_settings) -- that's a placeholder, not real ciphertext, and must
// never be passed to Open (it isn't valid Seal output) or re-sealed
// (turning ” into 28 bytes of real ciphertext would change what "unset"
// means to every reader that checks len(blob) == 0).
const minSealedBlobLen = 12 + 16

// ColumnReport is the outcome of rotating one sealed column.
type ColumnReport struct {
	Table        string
	Column       string
	Rewritten    int
	SkippedEmpty int // placeholder '' blobs (len < minSealedBlobLen), left untouched
	SkippedNull  int // NULL column value, left untouched
}

// Report is the outcome of a full Rotate call.
type Report struct {
	Columns []ColumnReport
}

// TotalRewritten sums Rewritten across every column.
func (r Report) TotalRewritten() int {
	n := 0
	for _, c := range r.Columns {
		n += c.Rewritten
	}
	return n
}

// Rotate re-encrypts every sealed column from oldEnc to newEnc inside a
// single transaction. Every row is decrypted with oldEnc, re-sealed with
// newEnc (a fresh random nonce, never reusing the old one), written back,
// then re-read and re-opened with newEnc to confirm the recovered
// plaintext is byte-identical to what was originally decrypted -- before
// any of it is allowed to commit.
//
// If dryRun is true, every step above still runs against a real
// transaction (so the caller gets real counts and real verification), but
// the transaction is rolled back instead of committed, leaving the
// database unchanged.
//
// The caller is responsible for ensuring no other process can write to
// the database concurrently (the panel itself must not be running --
// callers should hold store.AcquireSingletonLock first). Rotate does not
// take any locks of its own beyond the implicit row locks its own UPDATEs
// take within the transaction.
func Rotate(ctx context.Context, pool *pgxpool.Pool, oldEnc, newEnc *auth.Encryptor, dryRun bool) (Report, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	var report Report
	for _, sc := range sealedColumns {
		cr, err := rotateColumn(ctx, tx, sc, oldEnc, newEnc)
		if err != nil {
			return Report{}, fmt.Errorf("%s.%s: %w", sc.table, sc.column, err)
		}
		report.Columns = append(report.Columns, cr)
	}

	if dryRun {
		return report, nil // deferred Rollback discards every write above
	}
	if err := tx.Commit(ctx); err != nil {
		return Report{}, fmt.Errorf("commit: %w", err)
	}
	return report, nil
}

type pendingRow struct {
	keyVals   []any
	plaintext string
}

func rotateColumn(ctx context.Context, tx pgx.Tx, sc sealedColumn, oldEnc, newEnc *auth.Encryptor) (ColumnReport, error) {
	cr := ColumnReport{Table: sc.table, Column: sc.column}

	selectCols := append(append([]string{}, sc.keyCols...), sc.column)
	rows, err := tx.Query(ctx, fmt.Sprintf("SELECT %s FROM protean.%s", strings.Join(selectCols, ", "), sc.table))
	if err != nil {
		return cr, fmt.Errorf("select: %w", err)
	}

	var pending []pendingRow
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			rows.Close()
			return cr, fmt.Errorf("scan: %w", err)
		}
		keyVals := vals[:len(sc.keyCols)]
		blobVal := vals[len(sc.keyCols)]

		if blobVal == nil {
			cr.SkippedNull++
			continue
		}
		blob, ok := blobVal.([]byte)
		if !ok {
			rows.Close()
			return cr, fmt.Errorf("unexpected column type %T for %v", blobVal, keyVals)
		}
		if len(blob) < minSealedBlobLen {
			cr.SkippedEmpty++
			continue
		}
		plaintext, err := oldEnc.Open(blob)
		if err != nil {
			rows.Close()
			return cr, fmt.Errorf("open with old key (row %v): %w", keyVals, err)
		}
		pending = append(pending, pendingRow{keyVals: keyVals, plaintext: plaintext})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return cr, err
	}
	rows.Close()

	// keyWhere($base) builds "col1 = $base AND col2 = $base+1 ...", so the
	// same key-column list can be reused for both the UPDATE (blob is $1,
	// keys start at $2) and the verify SELECT (keys start at $1).
	keyWhere := func(base int) string {
		parts := make([]string, len(sc.keyCols))
		for i, k := range sc.keyCols {
			parts[i] = fmt.Sprintf("%s = $%d", k, base+i)
		}
		return strings.Join(parts, " AND ")
	}

	updateQuery := fmt.Sprintf("UPDATE protean.%s SET %s = $1 WHERE %s", sc.table, sc.column, keyWhere(2))
	for _, r := range pending {
		newBlob, err := newEnc.Seal(r.plaintext)
		if err != nil {
			return cr, fmt.Errorf("seal with new key (row %v): %w", r.keyVals, err)
		}
		args := append([]any{newBlob}, r.keyVals...)
		if _, err := tx.Exec(ctx, updateQuery, args...); err != nil {
			return cr, fmt.Errorf("update (row %v): %w", r.keyVals, err)
		}
	}

	// Verify pass: re-read (read-your-writes, within the same tx) and
	// confirm the new key recovers exactly the plaintext captured before
	// rewriting -- not just that Open succeeds, but that it's the SAME
	// secret, catching a rewrite that silently sealed the wrong row.
	verifyQuery := fmt.Sprintf("SELECT %s FROM protean.%s WHERE %s", sc.column, sc.table, keyWhere(1))
	for _, r := range pending {
		var blob []byte
		if err := tx.QueryRow(ctx, verifyQuery, r.keyVals...).Scan(&blob); err != nil {
			return cr, fmt.Errorf("verify select (row %v): %w", r.keyVals, err)
		}
		got, err := newEnc.Open(blob)
		if err != nil {
			return cr, fmt.Errorf("verify open with new key (row %v): %w", r.keyVals, err)
		}
		if got != r.plaintext {
			return cr, fmt.Errorf("verify mismatch (row %v): re-decrypted plaintext does not match the original", r.keyVals)
		}
	}

	cr.Rewritten = len(pending)
	return cr, nil
}

// Detect reports, for each sealed column with at least one populated row,
// whether enc can open that row. Read-only -- used to work out which key a
// database is currently on (e.g. after a rotation whose commit
// acknowledgement was lost to a network drop) without risking a write.
func Detect(ctx context.Context, pool *pgxpool.Pool, enc *auth.Encryptor) (map[string]bool, error) {
	result := make(map[string]bool, len(sealedColumns))
	for _, sc := range sealedColumns {
		key := sc.table + "." + sc.column
		query := fmt.Sprintf("SELECT %s FROM protean.%s WHERE %s IS NOT NULL LIMIT 1", sc.column, sc.table, sc.column)
		var blob []byte
		err := pool.QueryRow(ctx, query).Scan(&blob)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // no populated row for this column to check
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if len(blob) < minSealedBlobLen {
			continue // placeholder '', not real ciphertext
		}
		_, err = enc.Open(blob)
		result[key] = err == nil
	}
	return result, nil
}
