-- Periodic rx/tx counter snapshots per provider instance, for the traffic
-- history chart. Rate is derived at query time (delta between consecutive
-- samples); rows are pruned by the panel on a retention window (disk-space
-- knob, see TRAFFIC_RETENTION_HOURS) rather than kept forever.
CREATE TABLE IF NOT EXISTS protean.traffic_samples (
    id       bigserial   PRIMARY KEY,
    provider text        NOT NULL,   -- server:instance key
    ts       timestamptz NOT NULL,
    rx_bytes bigint      NOT NULL,
    tx_bytes bigint      NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traffic_samples_provider_ts
    ON protean.traffic_samples (provider, ts);
