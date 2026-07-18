-- Marks which servers row (if any) is the machine the panel itself runs
-- on -- distinct from "is a VPN node": the web SSH console needs a target
-- for the panel's own host (e.g. to run OS updates there), and that host
-- may or may not also be a registered VPN node. Reusing the servers row
-- avoids storing a second copy of the same SSH credentials when it does
-- coincide with one; a partial unique index enforces at most one flagged
-- row at the DB level (no application-level race possible).
ALTER TABLE protean.servers ADD COLUMN panel_host boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX servers_one_panel_host ON protean.servers (panel_host) WHERE panel_host;
