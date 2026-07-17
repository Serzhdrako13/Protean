package store

import (
	"context"
	"time"
)

type Subnet struct {
	ID        int64
	Provider  string
	CIDR      string
	Label     string
	CreatedAt time.Time
}

// ListAllSubnets returns the whole mesh-wide catalog of routable site
// networks, ordered by CIDR.
func (s *Store) ListAllSubnets(ctx context.Context) ([]Subnet, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, cidr::text, label, created_at
		FROM protean.subnets
		ORDER BY cidr
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var subnets []Subnet
	for rows.Next() {
		var sn Subnet
		if err := rows.Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.CreatedAt); err != nil {
			return nil, err
		}
		subnets = append(subnets, sn)
	}
	return subnets, rows.Err()
}

// CreateSubnet adds a network to the mesh-wide catalog.
func (s *Store) CreateSubnet(ctx context.Context, cidr, label string) (Subnet, error) {
	var sn Subnet
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.subnets (cidr, label)
		VALUES ($1, $2)
		RETURNING id, provider, cidr::text, label, created_at
	`, cidr, label).Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.CreatedAt)
	return sn, err
}

func (s *Store) DeleteSubnet(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.subnets WHERE id = $1`, id)
	return err
}
