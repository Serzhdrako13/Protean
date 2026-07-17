package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// AccessRequest is a portal user's request for access to one provider
// instance -- see the status meanings documented on the migration that
// creates protean.access_request.
type AccessRequest struct {
	ID        int64
	UserID    int64
	Username  string
	Provider  string
	Status    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// UpsertRequest creates a new request, or -- if one already exists for this
// (user, provider) pair (e.g. a prior denial) -- resets it back to pending.
// This is what powers the portal's "запросить снова" retry after a denial.
func (s *Store) UpsertRequest(ctx context.Context, userID int64, provider string) (AccessRequest, error) {
	var r AccessRequest
	err := s.pool.QueryRow(ctx, `
		INSERT INTO protean.access_request (user_id, provider, status, updated_at)
		VALUES ($1, $2, 'pending', now())
		ON CONFLICT (user_id, provider) DO UPDATE SET status = 'pending', updated_at = now()
		RETURNING id, user_id, provider, status, created_at, updated_at
	`, userID, provider).Scan(&r.ID, &r.UserID, &r.Provider, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// ListRequestsForUser returns every request a user has made, across all providers.
func (s *Store) ListRequestsForUser(ctx context.Context, userID int64) ([]AccessRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, provider, status, created_at, updated_at
		FROM protean.access_request WHERE user_id = $1
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		var r AccessRequest
		if err := rows.Scan(&r.ID, &r.UserID, &r.Provider, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAllRequests returns every request in the system, newest first, joined
// with the requesting user's username -- for the admin queue page.
func (s *Store) ListAllRequests(ctx context.Context) ([]AccessRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ar.id, ar.user_id, u.username, ar.provider, ar.status, ar.created_at, ar.updated_at
		FROM protean.access_request ar
		JOIN protean.users u ON u.id = ar.user_id
		ORDER BY ar.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessRequest
	for rows.Next() {
		var r AccessRequest
		if err := rows.Scan(&r.ID, &r.UserID, &r.Username, &r.Provider, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRequest fetches one request by id.
func (s *Store) GetRequest(ctx context.Context, id int64) (AccessRequest, error) {
	var r AccessRequest
	err := s.pool.QueryRow(ctx, `
		SELECT ar.id, ar.user_id, u.username, ar.provider, ar.status, ar.created_at, ar.updated_at
		FROM protean.access_request ar
		JOIN protean.users u ON u.id = ar.user_id
		WHERE ar.id = $1
	`, id).Scan(&r.ID, &r.UserID, &r.Username, &r.Provider, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, ErrNotFound
	}
	return r, err
}

// DeleteRequest removes one request row outright -- callers must enforce
// which statuses this is safe for (see api_access_requests.go's
// apiAccessRequestDelete: only 'denied', never pending/approved/granted).
func (s *Store) DeleteRequest(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM protean.access_request WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRequestStatus updates a request's status (approved/granted/denied).
func (s *Store) SetRequestStatus(ctx context.Context, id int64, status string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE protean.access_request SET status = $2, updated_at = now() WHERE id = $1
	`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FindApprovedRequestForProvider returns the oldest "approved" (awaiting a
// manually-created peer) request for a provider, if any -- surfaced on
// ProviderDetailPage as a "create a client for this user" prompt.
func (s *Store) FindApprovedRequestForProvider(ctx context.Context, provider string) (AccessRequest, bool, error) {
	var r AccessRequest
	err := s.pool.QueryRow(ctx, `
		SELECT ar.id, ar.user_id, u.username, ar.provider, ar.status, ar.created_at, ar.updated_at
		FROM protean.access_request ar
		JOIN protean.users u ON u.id = ar.user_id
		WHERE ar.provider = $1 AND ar.status = 'approved'
		ORDER BY ar.created_at ASC
		LIMIT 1
	`, provider).Scan(&r.ID, &r.UserID, &r.Username, &r.Provider, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, false, nil
	}
	if err != nil {
		return AccessRequest{}, false, err
	}
	return r, true, nil
}
