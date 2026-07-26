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
	// GroupID is this instance's network group, if any -- see
	// SetProviderGroup; never touched by SetProviderSettings.
	GroupID *int64
}

// GetProviderSettings returns settings for a provider, defaulting to all-off
// when no row exists yet.
func (s *Store) GetProviderSettings(ctx context.Context, provider string) (ProviderSettings, error) {
	ps := ProviderSettings{Provider: provider}
	err := s.pool.QueryRow(ctx, `
		SELECT mesh_enabled, internet_egress, auto_assign_start, auto_assign_end, group_id
		FROM protean.provider_settings WHERE provider = $1
	`, provider).Scan(&ps.MeshEnabled, &ps.InternetEgress, &ps.AutoAssignStart, &ps.AutoAssignEnd, &ps.GroupID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ps, nil // no row -> defaults (standalone parallel tunnel)
	}
	if err != nil {
		return ProviderSettings{}, err
	}
	return ps, nil
}

// SetProviderSettings upserts the toggles for a provider. Deliberately
// never touches group_id -- that's SetProviderGroup's job alone, so this
// generic settings save can never accidentally clear/overwrite a group
// assignment as a side effect.
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

// SetProviderGroup persists a provider instance's network group (nil
// clears it). Works even when no provider_settings row exists yet
// (defaults everything else to off/empty on first insert).
func (s *Store) SetProviderGroup(ctx context.Context, provider string, groupID *int64) (ProviderSettings, error) {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO protean.provider_settings (provider, group_id, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (provider) DO UPDATE SET group_id = EXCLUDED.group_id, updated_at = now()
	`, provider, groupID)
	if err != nil {
		return ProviderSettings{}, err
	}
	return s.GetProviderSettings(ctx, provider)
}
