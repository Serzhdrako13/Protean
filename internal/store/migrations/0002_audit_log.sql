CREATE TABLE wgpanel.audit_log (
    id       BIGSERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    username TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_ts_idx ON wgpanel.audit_log (ts DESC);
