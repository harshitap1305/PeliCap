-- PaliCap Alert Schema
-- Applied automatically on first postgres container startup
-- via /docker-entrypoint-initdb.d/

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        BIGINT PRIMARY KEY,
    type            SMALLINT NOT NULL,
    severity        SMALLINT NOT NULL,
    timestamp_ns    BIGINT   NOT NULL,
    title           TEXT     NOT NULL,
    description     TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    domain          TEXT,
    endpoint        TEXT,
    observed_value  DOUBLE PRECISION,
    threshold_value DOUBLE PRECISION,
    baseline_value  DOUBLE PRECISION,
    correlation_id  BIGINT,
    is_ongoing      BOOLEAN  DEFAULT TRUE,
    resolved_at_ns  BIGINT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_type     ON alerts(type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_corr     ON alerts(correlation_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src      ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst      ON alerts(dst_ip);
