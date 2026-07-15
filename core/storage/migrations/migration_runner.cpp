#include "migration_runner.hpp"
#include <iostream>

namespace storage {

MigrationRunner::MigrationRunner(PgConnectionPool& pool) : pool_(pool) {
    migrations_.push_back({
        1,
        "Initial schema",
        R"(
            CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
            CREATE EXTENSION IF NOT EXISTS pg_trgm CASCADE;

            -- capture_sessions
            CREATE TABLE IF NOT EXISTS capture_sessions (
                session_id UUID PRIMARY KEY,
                start_time TIMESTAMPTZ NOT NULL,
                end_time TIMESTAMPTZ,
                interface_name TEXT NOT NULL,
                bpf_filter TEXT,
                packets_captured BIGINT DEFAULT 0,
                packets_dropped BIGINT DEFAULT 0
            );
            
            -- flows
            CREATE TABLE IF NOT EXISTS flows (
                flow_id BIGINT,
                start_time TIMESTAMPTZ NOT NULL,
                src_ip INET,
                dst_ip INET,
                src_port INTEGER,
                dst_port INTEGER,
                protocol SMALLINT,
                interface_name TEXT,
                end_time TIMESTAMPTZ,
                duration_ms INTEGER,
                fwd_packets BIGINT,
                rev_packets BIGINT,
                fwd_bytes BIGINT,
                rev_bytes BIGINT,
                payload_bytes BIGINT,
                tcp_state SMALLINT,
                avg_rtt_us INTEGER,
                min_rtt_us INTEGER,
                retransmit_count INTEGER,
                zero_window_events INTEGER,
                app_protocol SMALLINT,
                tls_sni TEXT,
                http_host TEXT,
                dns_query TEXT,
                tags JSONB,
                session_id UUID NOT NULL,
                PRIMARY KEY (flow_id, start_time)
            );

            SELECT create_hypertable('flows', 'start_time', if_not_exists => TRUE);
            SELECT add_retention_policy('flows', INTERVAL '30 days', if_not_exists => TRUE);

            CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows (src_ip, start_time DESC);
            CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows (dst_ip, start_time DESC);
            CREATE INDEX IF NOT EXISTS idx_flows_dst_port ON flows (dst_port, start_time DESC);
            CREATE INDEX IF NOT EXISTS idx_flows_session_id ON flows (session_id, start_time DESC);

            -- Trigram indexes for fast ILIKE and Regex text search
            CREATE INDEX IF NOT EXISTS idx_flows_tls_sni_trgm ON flows USING GIN (tls_sni gin_trgm_ops) WHERE tls_sni IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_flows_http_host_trgm ON flows USING GIN (http_host gin_trgm_ops) WHERE http_host IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_flows_dns_query_trgm ON flows USING GIN (dns_query gin_trgm_ops) WHERE dns_query IS NOT NULL;

            -- metrics
            CREATE TABLE IF NOT EXISTS metrics (
                time TIMESTAMPTZ NOT NULL,
                metric_name TEXT NOT NULL,
                interface_name TEXT,
                value_avg DOUBLE PRECISION,
                value_min DOUBLE PRECISION,
                value_max DOUBLE PRECISION,
                value_p95 DOUBLE PRECISION,
                sample_count INTEGER,
                PRIMARY KEY (metric_name, time)
            );

            SELECT create_hypertable('metrics', 'time', if_not_exists => TRUE);
            SELECT add_retention_policy('metrics', INTERVAL '90 days', if_not_exists => TRUE);

            -- alerts
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id BIGINT PRIMARY KEY,
                type SMALLINT,
                severity SMALLINT,
                timestamp_ns BIGINT,
                title TEXT,
                description TEXT,
                src_ip INET,
                dst_ip INET,
                domain TEXT,
                endpoint TEXT,
                observed_value DOUBLE PRECISION,
                threshold_value DOUBLE PRECISION,
                baseline_value DOUBLE PRECISION,
                correlation_id BIGINT,
                is_ongoing BOOLEAN,
                session_id UUID NOT NULL
            );

            -- PCAP index
            CREATE TABLE IF NOT EXISTS pcap_files (
                file_id BIGSERIAL PRIMARY KEY,
                filename TEXT NOT NULL,
                start_time TIMESTAMPTZ,
                end_time TIMESTAMPTZ,
                file_size_bytes BIGINT,
                packet_count BIGINT,
                is_compressed BOOLEAN,
                is_deleted BOOLEAN DEFAULT false
            );
        )"
    });
    
    migrations_.push_back({
        2,
        "Fix port types",
        R"(
            ALTER TABLE flows ALTER COLUMN src_port TYPE INTEGER;
            ALTER TABLE flows ALTER COLUMN dst_port TYPE INTEGER;
        )"
    });
}

bool MigrationRunner::run_all() {
    try {
        auto conn_proxy = pool_.acquire();
        pqxx::connection& conn = *conn_proxy;
        
        ensure_migrations_table(conn);
        int current_version = get_current_version(conn);

        for (const auto& m : migrations_) {
            if (m.version > current_version) {
                apply_migration(conn, m);
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[MigrationRunner] Failed: " << e.what() << "\n";
        return false;
    }
}

void MigrationRunner::ensure_migrations_table(pqxx::connection& conn) {
    pqxx::work tx(conn);
    tx.exec(R"(
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMPTZ DEFAULT NOW(),
            description TEXT
        )
    )");
    tx.commit();
}

int MigrationRunner::get_current_version(pqxx::connection& conn) {
    pqxx::work tx(conn);
    auto res = tx.exec("SELECT COALESCE(MAX(version), 0) FROM schema_migrations");
    return res[0][0].as<int>();
}

void MigrationRunner::apply_migration(pqxx::connection& conn, const Migration& m) {
    std::cout << "[MigrationRunner] Applying migration " << m.version << ": " << m.description << "\n";
    pqxx::work tx(conn);
    tx.exec(m.sql);
    
    tx.exec("INSERT INTO schema_migrations (version, description) VALUES ($1, $2)",
            pqxx::params{m.version, m.description});
    tx.commit();
}

} // namespace storage
