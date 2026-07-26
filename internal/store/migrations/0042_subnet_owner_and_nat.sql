-- Links a catalogued subnet to the Node (router/equipment) fronting it, and
-- adds a per-subnet NAT mode so an admin unifying multiple site subnets
-- behind different routers into one routable mesh can choose, per subnet,
-- whether the SERVER masquerades that subnet's outbound-to-mesh traffic
-- ("masquerade" -- the far router never needs a route back for the true
-- source subnet) or leaves source addresses untouched ("passthrough" --
-- both routers must have their own reciprocal routes, entirely the
-- operator's own responsibility on their own hardware; Protean can never
-- push config to an adopted router's own device). Defaults to
-- "passthrough" so every existing catalogued subnet keeps today's exact
-- (zero-NAT) behavior -- this migration introduces no new masquerading.
ALTER TABLE protean.subnets
    ADD COLUMN owner_node_id BIGINT REFERENCES protean.nodes(id) ON DELETE SET NULL;

CREATE INDEX subnets_owner_node_id_idx ON protean.subnets (owner_node_id)
    WHERE owner_node_id IS NOT NULL;

ALTER TABLE protean.subnets
    ADD COLUMN nat_mode TEXT NOT NULL DEFAULT 'passthrough'
        CHECK (nat_mode IN ('passthrough', 'masquerade'));
