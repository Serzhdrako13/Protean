package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ProviderSettings holds per-provider network toggles. Absent rows mean
// defaults (both false, empty range) -- a standalone parallel tunnel with
// no restriction on auto-assigned addresses.
type ProviderSettings struct {
	Provider       string
	MeshEnabled    bool
	InternetEgress bool
	// AutoAssignStart/AutoAssignEnd bound where auto-provisioning (portal
	// access grants, node grants) picks a free address from -- empty means
	// "start of subnet"/"end of subnet" respectively (i.e. no restriction).
	AutoAssignStart string
	AutoAssignEnd   string
}

// GetProviderSettings returns settings for a provider, defaulting to all-off
// when no row exists yet.
func (s *Store) GetProviderSettings(ctx context.Context, provider string) (ProviderSettings, error) {
	ps := ProviderSettings{Provider: provider}
	err := s.pool.QueryRow(ctx, `
		SELECT mesh_enabled, internet_egress, auto_assign_start, auto_assign_end
		FROM protean.provider_settings WHERE provider = $1
	`, provider).Scan(&ps.MeshEnabled, &ps.InternetEgress, &ps.AutoAssignStart, &ps.AutoAssignEnd)
	if errors.Is(err, pgx.ErrNoRows) {
		return ps, nil // no row -> defaults (standalone parallel tunnel)
	}
	if err != nil {
		return ProviderSettings{}, err
	}
	return ps, nil
}

// SetProviderSettings upserts the toggles for a provider.
func (s *Store) SetProviderSettings(ctx context.Context, ps ProviderSettings) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.provider_settings (provider, mesh_enabled, internet_egress, auto_assign_start, auto_assign_end, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (provider) DO UPDATE SET
			mesh_enabled = EXCLUDED.mesh_enabled,
			internet_egress = EXCLUDED.internet_egress,
			auto_assign_start = EXCLUDED.auto_assign_start,
			auto_assign_end = EXCLUDED.auto_assign_end,
			updated_at = now()
	`, ps.Provider, ps.MeshEnabled, ps.InternetEgress, ps.AutoAssignStart, ps.AutoAssignEnd)
	return err
}
