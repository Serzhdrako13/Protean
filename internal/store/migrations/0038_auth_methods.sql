-- Pluggable login methods: Internal (local password, unchanged default)
-- alongside optional LDAP/AD and OIDC, independently toggleable. LDAP/OIDC
-- accounts are deliberately separate entities from local ones even when
-- the username matches -- hence auth_source joins username in the unique
-- key instead of a global username-only uniqueness.
ALTER TABLE wgpanel.users
    ADD COLUMN auth_source text NOT NULL DEFAULT 'local'
        CHECK (auth_source IN ('local', 'ldap', 'oidc'));
ALTER TABLE wgpanel.users ALTER COLUMN password_hash DROP NOT NULL; -- external accounts have none
ALTER TABLE wgpanel.users DROP CONSTRAINT users_username_key;
ALTER TABLE wgpanel.users ADD CONSTRAINT users_auth_source_username_key UNIQUE (auth_source, username);

-- Singleton toggle for local username/password login. Exists mainly so it
-- can be turned OFF once LDAP/OIDC is trusted -- the EMERGENCY_ADMIN_*
-- env vars (internal/config, internal/auth/manager.go) are the break-glass
-- path that keeps working even while this is disabled.
CREATE TABLE wgpanel.internal_auth_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE wgpanel.ldap_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled boolean NOT NULL DEFAULT false,
    url text NOT NULL DEFAULT '',              -- ldap://host:389 or ldaps://host:636
    skip_tls_verify boolean NOT NULL DEFAULT false,
    bind_dn text NOT NULL DEFAULT '',          -- service account used for the user search
    enc_bind_password bytea NOT NULL DEFAULT '',
    user_base_dn text NOT NULL DEFAULT '',
    user_filter text NOT NULL DEFAULT '(uid=%s)',
    group_base_dn text NOT NULL DEFAULT '',    -- fallback group search, used only if memberOf is absent
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE wgpanel.oidc_settings (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    enabled boolean NOT NULL DEFAULT false,
    issuer_url text NOT NULL DEFAULT '',
    client_id text NOT NULL DEFAULT '',
    enc_client_secret bytea NOT NULL DEFAULT '',
    scopes text NOT NULL DEFAULT 'openid profile email groups',
    username_claim text NOT NULL DEFAULT 'preferred_username',
    groups_claim text NOT NULL DEFAULT 'groups',
    redirect_base_url text NOT NULL DEFAULT '', -- e.g. https://vpn.example.com -- builds the callback redirect_uri
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- One row per configured group, scoped by method+role -- same
-- dedicated-list-table idiom as login_ip_rules rather than an array/CSV
-- column. No match in either role's list for a given method -> login is
-- denied outright (see internal/auth/manager.go's resolveRole).
CREATE TABLE wgpanel.auth_group_rules (
    method      text NOT NULL CHECK (method IN ('ldap', 'oidc')),
    role        text NOT NULL CHECK (role IN ('admin', 'user')),
    group_value text NOT NULL, -- LDAP: group DN. OIDC: claim value (group name/id).
    PRIMARY KEY (method, role, group_value)
);
