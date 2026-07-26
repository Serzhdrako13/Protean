package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type Subnet struct {
	ID          int64
	Provider    string
	CIDR        string
	Label       string
	OwnerNodeID *int64
	NATMode     string
	CreatedAt   time.Time
}

// ListAllSubnets returns the whole mesh-wide catalog of routable site
// networks, ordered by CIDR.
func (s *Store) ListAllSubnets(ctx context.Context) ([]Subnet, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, provider, cidr::text, label, owner_node_id, nat_mode, created_at
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
		if err := rows.Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.OwnerNodeID, &sn.NATMode, &sn.CreatedAt); err != nil {
			return nil, err
		}
		subnets = append(subnets, sn)
	}
	return subnets, rows.Err()
}

// GetSubnet fetches one subnet by id. Returns ErrNotFound if it doesn't exist.
func (s *Store) GetSubnet(ctx context.Context, id int64) (Subnet, error) {
	var sn Subnet
	err := s.pool.QueryRow(ctx, `
		SELECT id, provider, cidr::text, label, owner_node_id, nat_mode, created_at
		FROM protean.subnets WHERE id = $1
	`, id).Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.OwnerNodeID, &sn.NATMode, &sn.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subnet{}, ErrNotFound
	}
	return sn, err
}

// CreateSubnet adds a network to the mesh-wide catalog. provider is the
// "server:instance" key this subnet is routed through if known (empty for
// a manually-catalogued subnet with no known adopted router). ownerNodeID
// is the Node fronting it if known (nil otherwise).
func (s *Store) CreateSubnet(ctx context.Context, provider, cidr, label string, ownerNodeID *int64) (Subnet, error) {
	var sn Subnet
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.subnets (provider, cidr, label, owner_node_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id, provider, cidr::text, label, owner_node_id, nat_mode, created_at
	`, provider, cidr, label, ownerNodeID).Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.OwnerNodeID, &sn.NATMode, &sn.CreatedAt)
	return sn, err
}

// SetSubnetNATMode persists a subnet's NAT mode. Returns ErrNotFound if the
// subnet doesn't exist. Purely a DB write -- the API layer is responsible
// for applying/tearing down the live iptables rule via Installer.SubnetNAT.
func (s *Store) SetSubnetNATMode(ctx context.Context, id int64, mode string) (Subnet, error) {
	var sn Subnet
	err := s.pool.QueryRow(ctx, `
		UPDATE protean.subnets SET nat_mode = $2 WHERE id = $1
		RETURNING id, provider, cidr::text, label, owner_node_id, nat_mode, created_at
	`, id, mode).Scan(&sn.ID, &sn.Provider, &sn.CIDR, &sn.Label, &sn.OwnerNodeID, &sn.NATMode, &sn.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subnet{}, ErrNotFound
	}
	return sn, err
}

func (s *Store) DeleteSubnet(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.subnets WHERE id = $1`, id)
	return err
}
