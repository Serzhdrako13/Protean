package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// NetworkGroup is a shared, admin-visible name for a set of provider
// instances + subnets that together form one routable network -- see
// migration 0043 for the full reasoning.
type NetworkGroup struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

func (s *Store) CreateNetworkGroup(ctx context.Context, name string) (NetworkGroup, error) {
	var g NetworkGroup
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.network_groups (name) VALUES ($1)
		RETURNING id, name, created_at
	`, name).Scan(&g.ID, &g.Name, &g.CreatedAt)
	return g, err
}

func (s *Store) ListNetworkGroups(ctx context.Context) ([]NetworkGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, created_at FROM protean.network_groups ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []NetworkGroup
	for rows.Next() {
		var g NetworkGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// GetNetworkGroup fetches one group by id. Returns ErrNotFound if it
// doesn't exist.
func (s *Store) GetNetworkGroup(ctx context.Context, id int64) (NetworkGroup, error) {
	var g NetworkGroup
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, created_at FROM protean.network_groups WHERE id = $1
	`, id).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return NetworkGroup{}, ErrNotFound
	}
	return g, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// CreateNextAutoNamedGroup creates a new group named "Сеть {N}", N being
// one more than the current group count -- used by network detection and
// mesh-linking to auto-name a newly-unified network without asking the
// admin. name is UNIQUE; a race between two concurrent callers computing
// the same N retries with N+1 rather than failing the whole caller
// outright.
func (s *Store) CreateNextAutoNamedGroup(ctx context.Context) (NetworkGroup, error) {
	groups, err := s.ListNetworkGroups(ctx)
	if err != nil {
		return NetworkGroup{}, err
	}
	n := len(groups) + 1
	for attempt := 0; attempt < 20; attempt++ {
		g, err := s.CreateNetworkGroup(ctx, fmt.Sprintf("Сеть %d", n))
		if err == nil {
			return g, nil
		}
		if !isUniqueViolation(err) {
			return NetworkGroup{}, err
		}
		n++
	}
	return NetworkGroup{}, fmt.Errorf("could not find a free auto-generated group name after 20 attempts")
}

// ListAllProviderGroupNames returns every provider instance's assigned
// group NAME (joined against network_groups), keyed by provider -- for
// bulk population mirroring ListAllServerInstanceLabels. Instances with
// no group are simply absent from the map.
func (s *Store) ListAllProviderGroupNames(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ps.provider, g.name
		FROM protean.provider_settings ps
		JOIN protean.network_groups g ON g.id = ps.group_id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var provider, name string
		if err := rows.Scan(&provider, &name); err != nil {
			return nil, err
		}
		out[provider] = name
	}
	return out, rows.Err()
}
