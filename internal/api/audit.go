package api

import (
	"context"
	"log/slog"
)

// audit records an admin action, attributed to the logged-in user. It's
// best-effort: a failure to write the audit row is logged but never blocks
// the action the user asked for.
func (s *Server) audit(ctx context.Context, action, target string) {
	username := usernameFromContext(ctx)
	if err := s.store.AddAuditEntry(ctx, username, action, target); err != nil {
		slog.Error("audit write failed", "action", action, "user", username, "err", err)
	}
}
