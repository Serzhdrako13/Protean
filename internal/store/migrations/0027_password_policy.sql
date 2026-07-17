-- Configurable password policy: minimum length/complexity + optional
-- forced periodic change. password_changed_at drives max_age_days
-- enforcement (internal/api/api_common.go's requireAuthAPI gate) --
-- existing users get `now()` as a starting point via the column default,
-- not treated as already-overdue on the day this migration runs.
ALTER TABLE protean.users ADD COLUMN password_changed_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE protean.password_policy_settings (
    id             boolean PRIMARY KEY DEFAULT true CHECK (id),
    min_length     int NOT NULL DEFAULT 8,
    require_upper  boolean NOT NULL DEFAULT false,
    require_lower  boolean NOT NULL DEFAULT false,
    require_digit  boolean NOT NULL DEFAULT false,
    require_symbol boolean NOT NULL DEFAULT false,
    -- max_age_days: 0 = no forced expiry (default -- most self-hosted admin
    -- panels don't want periodic rotation by default, it's an opt-in
    -- hardening knob, not a default nuisance).
    max_age_days   int NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
