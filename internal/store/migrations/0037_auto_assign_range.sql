-- Per-provider "DHCP pool" style restriction on auto-assigned addresses
-- (portal access grants, node grants) -- empty means "whole subnet",
-- unchanged behavior from before this column existed.
ALTER TABLE wgpanel.provider_settings ADD COLUMN auto_assign_start TEXT NOT NULL DEFAULT '';
ALTER TABLE wgpanel.provider_settings ADD COLUMN auto_assign_end   TEXT NOT NULL DEFAULT '';
