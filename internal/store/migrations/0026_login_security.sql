-- Login brute-force protection: configurable progressive bans (by username
-- and/or by IP), an admin-managed IP allow/deny list, and an append-only
-- attempt log that doubles as the audit trail + stats source. Replaces the
-- old hardcoded in-memory internal/auth.LoginLimiter (5 attempts/5min,
-- IP-only, reset on every restart) entirely.

-- Singleton settings row (id enforced true, same pattern as tls_state).
CREATE TABLE protean.login_security_settings (
    id                       boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled                  boolean NOT NULL DEFAULT true,
    track_by_username        boolean NOT NULL DEFAULT true,
    track_by_ip              boolean NOT NULL DEFAULT true,
    -- fail_threshold wrong attempts within count_window_minutes trigger a ban.
    fail_threshold           int NOT NULL DEFAULT 3,
    count_window_minutes     int NOT NULL DEFAULT 5,
    -- First ban is ban_base_minutes. Each re-violation within
    -- escalation_reset_minutes of the PREVIOUS ban's expiry multiplies the
    -- duration by escalation_factor (so 5 -> 10 -> 20 -> 40... by default);
    -- going escalation_reset_minutes or longer without a new violation resets
    -- back to the base duration. max_ban_minutes caps the escalation so a
    -- persistent attacker can't accidentally lock an account out forever.
    ban_base_minutes         int NOT NULL DEFAULT 5,
    escalation_factor        double precision NOT NULL DEFAULT 2,
    escalation_reset_minutes int NOT NULL DEFAULT 60,
    max_ban_minutes          int NOT NULL DEFAULT 1440,
    updated_at               timestamptz NOT NULL DEFAULT now()
);

-- Admin-managed IP allow/deny list. deny is checked first and rejects
-- outright (no attempt even reaches auth.Manager.Login); allow exempts an
-- IP from ban tracking entirely (e.g. a trusted office network) but attempts
-- are still logged. ip_or_cidr may be a bare IP or a CIDR range -- membership
-- is checked in Go (net.ParseCIDR/Contains), not in SQL, since this list is
-- small and admin-curated.
CREATE TABLE protean.login_ip_rules (
    ip_or_cidr text PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('allow', 'deny')),
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only log of every login attempt -- the source of truth for both
-- the failure-counting window (COUNT ... WHERE ts > now() - window) and the
-- admin-facing stats/recent-activity view. reason is one of:
-- 'bad_password', 'bad_totp', '' (success), 'banned' (rejected -- already
-- under an active ban), 'ip_denied' (rejected by the deny list).
CREATE TABLE protean.login_attempts (
    id       bigserial PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    username text NOT NULL DEFAULT '',
    ip       text NOT NULL DEFAULT '',
    success  boolean NOT NULL,
    reason   text NOT NULL DEFAULT ''
);
CREATE INDEX login_attempts_ts_idx ON protean.login_attempts (ts);
CREATE INDEX login_attempts_username_idx ON protean.login_attempts (username, ts);
CREATE INDEX login_attempts_ip_idx ON protean.login_attempts (ip, ts);

-- Current ban state per key (one row per username or IP that has ever been
-- banned) -- banned_until in the past simply means "not currently banned",
-- rows are kept (not deleted) so escalation_level/last known ban is
-- available the next time this key re-offends.
CREATE TABLE protean.login_ban_state (
    key_type         text NOT NULL CHECK (key_type IN ('username', 'ip')),
    key_value        text NOT NULL,
    banned_until     timestamptz NOT NULL,
    escalation_level int NOT NULL DEFAULT 0,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_type, key_value)
);
