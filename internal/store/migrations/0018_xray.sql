-- Xray (DPI-resistant) provider instances. One active strategy per instance;
-- params (which include secrets: reality private key, passwords) are stored
-- AES-encrypted as a whole JSON blob. relay is the optional foreign egress
-- relay spec (also encrypted; NULL = direct egress).
CREATE TABLE IF NOT EXISTS wgpanel.xray_instances (
    provider    text        PRIMARY KEY,   -- server:instance key
    strategy    text        NOT NULL,
    enc_params  bytea       NOT NULL,       -- AES(JSON params)
    enc_relay   bytea,                      -- AES(JSON RelaySpec), NULL = direct
    updated_at  timestamptz NOT NULL DEFAULT now()
);
