-- Session lifetime was previously a hardcoded 30-day constant
-- (auth.SessionTTL) -- admin-configurable now, alongside the other
-- account-security-lifecycle settings in this same table.
ALTER TABLE protean.password_policy_settings ADD COLUMN session_ttl_hours INT NOT NULL DEFAULT 720;
