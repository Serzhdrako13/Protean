-- Named "network groups" ("Сеть 1", "Сеть 2", ...): a shared, admin-visible
-- name for a set of provider instances + subnets that together form one
-- routable network -- e.g. everything unified behind one adopted
-- WireGuard instance's routers, or two instances joined by Mesh. Distinct
-- from MeshEnabled/InternetEgress (which only ever describe THIS
-- instance's own on/off participation, never a shared identity across
-- instances) and distinct from Subnet.Label (free text, no shared
-- identity across rows).
CREATE TABLE protean.network_groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE protean.subnets
    ADD COLUMN group_id BIGINT REFERENCES protean.network_groups(id) ON DELETE SET NULL;

CREATE INDEX subnets_group_id_idx ON protean.subnets (group_id)
    WHERE group_id IS NOT NULL;

ALTER TABLE protean.provider_settings
    ADD COLUMN group_id BIGINT REFERENCES protean.network_groups(id) ON DELETE SET NULL;

CREATE INDEX provider_settings_group_id_idx ON protean.provider_settings (group_id)
    WHERE group_id IS NOT NULL;
