-- Disabling a server (distinct from deleting it) stops the panel from
-- connecting to it / registering its providers, but keeps every
-- server_instances row and all provider-keyed settings intact -- re-enabling
-- just reconnects with everything as it was. See internal/api/api_servers.go
-- for the full three-state design (enabled / disabled / deleted).
ALTER TABLE wgpanel.servers ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT true;
