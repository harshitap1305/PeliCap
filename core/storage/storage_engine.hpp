#pragma once
#include "pg_connection_pool.hpp"
#include "write_queue.hpp"
#include "batch_writer.hpp"
#include "migrations/migration_runner.hpp"
#include "pcap_file_manager.hpp"
#include "retention/retention_manager.hpp"
#include "../capture/packet.hpp"
#include "../flow/flow.hpp"
#include "../detection/alert.hpp"
#include <memory>
#include <string>
#include <nlohmann/json.hpp>

namespace storage {

class StorageEngine {
public:
    StorageEngine(const std::string& pg_dsn, const std::string& pcap_dir);
    ~StorageEngine();

    void start();
    void stop();

    // Enqueue for batch write (non-blocking, lock-free)
    void write_flow(std::shared_ptr<Flow> flow_ptr);
    void write_alert(std::shared_ptr<Alert> alert_ptr);
    void write_metrics_snapshot(std::shared_ptr<void> metrics_ptr);

    struct SessionStart {
        std::string session_id;
        int64_t start_time_ns;
        std::string interface_name;
        std::string bpf_filter;
    };
    void write_session_start(std::shared_ptr<SessionStart> session_ptr);

    // Direct PCAP write (called from hot packet path — no blocking)
    void write_raw_packet(const CapturedPacket& packet);

    // REST API query methods
    nlohmann::json query_flows(int limit = 50, int offset = 0);
    nlohmann::json query_metrics_history(const std::string& metric_name, const std::string& resolution = "1m");
    nlohmann::json get_status();

    PgConnectionPool& get_pool() { return *pool_; }

private:
    std::string pg_dsn_;
    std::unique_ptr<PgConnectionPool> pool_;
    std::unique_ptr<MigrationRunner> migration_runner_;
    std::unique_ptr<WriteQueue> queue_;
    std::unique_ptr<BatchWriter> batch_writer_;
    std::unique_ptr<PcapFileManager> pcap_manager_;
    std::unique_ptr<RetentionManager> retention_manager_;
};

} // namespace storage
