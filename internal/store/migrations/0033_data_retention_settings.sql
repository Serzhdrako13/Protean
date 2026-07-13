-- Configurable auto-cleanup for data that otherwise accumulates without
-- bound. Each category is opt-in (enabled defaults false) -- deletes are
-- one-way, so nothing is removed until an admin explicitly turns a
-- category on (or uses the manual "clean up now" action). Only terminal/
-- inactive rows are ever eligible regardless of age -- see
-- internal/api/data_retention.go for exactly what "eligible" means per
-- category (e.g. only 'denied' access requests, never pending/approved/
-- granted; only bans whose banned_until has already passed, never an
-- active/future ban).
CREATE TABLE wgpanel.data_retention_settings (
    id                      boolean PRIMARY KEY DEFAULT true CHECK (id),
    access_requests_enabled boolean NOT NULL DEFAULT false,
    access_requests_days    int NOT NULL DEFAULT 90,
    audit_log_enabled       boolean NOT NULL DEFAULT false,
    audit_log_days          int NOT NULL DEFAULT 365,
    login_attempts_enabled  boolean NOT NULL DEFAULT false,
    login_attempts_days     int NOT NULL DEFAULT 30,
    login_bans_enabled      boolean NOT NULL DEFAULT false,
    login_bans_days         int NOT NULL DEFAULT 90,
    updated_at              timestamptz NOT NULL DEFAULT now()
);
