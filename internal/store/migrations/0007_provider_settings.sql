-- Per-provider network settings, decided independently for each VPN:
--   mesh_enabled     -- join the cross-provider no-NAT mesh (off => the VPN
--                       runs as an independent parallel tunnel)
--   internet_egress  -- route clients out to the internet through this VPN
--                       (hub NATs; clients get a default route)
-- Both default off: a fresh VPN is a standalone parallel tunnel that does not
-- merge networks and does not provide internet egress.
CREATE TABLE protean.provider_settings (
    provider        TEXT PRIMARY KEY,
    mesh_enabled    BOOLEAN NOT NULL DEFAULT false,
    internet_egress BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
