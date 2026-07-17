package store

import (
	"context"
	"time"
)

// Node is a non-portal, non-login equipment identity ("Узел") -- a router
// or other device that connects as a VPN peer, but never logs into the
// portal and never goes through the access-request pending/approved dance
// (an admin grants/revokes its provider access directly). Kept in its own
// table rather than folded into users -- see the plan doc.
type Node struct {
	ID          int64
	Name        string
	// Kind: "router" | "device" | "other". "device" covers an external
	// server/machine that's just a VPN client peer -- deliberately not
	// called "server" to avoid confusion with the SSH-managed hosts on
	// the Servers page.
	Kind string
	// Role: "member" (a plain peer, same NAT handling as any client) or
	// "network_node" (a full network participant with its own subnet
	// behind it -- see HasNetworkNodePeer for the safety invariant this
	// role implies).
	Role        string
	Description string
	CreatedAt   time.Time
}

func (s *Store) CreateNode(ctx context.Context, n Node) (Node, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.nodes (name, kind, role, description)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at
	`, n.Name, n.Kind, n.Role, n.Description).Scan(&n.ID, &n.CreatedAt)
	return n, err
}

func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, kind, role, description, created_at FROM protean.nodes ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.Kind, &n.Role, &n.Description, &n.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) GetNode(ctx context.Context, id int64) (Node, error) {
	var n Node
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, kind, role, description, created_at FROM protean.nodes WHERE id = $1
	`, id).Scan(&n.ID, &n.Name, &n.Kind, &n.Role, &n.Description, &n.CreatedAt)
	if err != nil {
		return Node{}, ErrNotFound
	}
	return n, nil
}

func (s *Store) UpdateNode(ctx context.Context, id int64, name, kind, role, description string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.nodes SET name = $2, kind = $3, role = $4, description = $5 WHERE id = $1
	`, id, name, kind, role, description)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM protean.nodes WHERE id = $1`, id)
	return err
}
