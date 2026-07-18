#include "storage_engine.hpp"
#include <iostream>

namespace storage {

// ── internal helpers ──────────────────────────────────────────────────────────
// We need a place to keep the shared_ptr alive between enqueue and dequeue.
// Strategy: heap-allocate a shared_ptr, store the raw pointer in the queue.
// BatchWriter reclaims ownership via the shared_block pointer.

template<typename T>
static StorageEvent make_event(EventType type, std::shared_ptr<T> ptr) {
    // Heap-allocate a copy of the shared_ptr — this keeps the refcount alive.
    auto* heap = new std::shared_ptr<T>(std::move(ptr));
    StorageEvent ev;
    ev.type         = type;
    ev.data_ptr     = static_cast<void*>(heap->get());
    ev.shared_block = static_cast<void*>(heap);
    return ev;
}

// ── StorageEngine ─────────────────────────────────────────────────────────────

StorageEngine::StorageEngine(const std::string& pg_dsn, const std::string& pcap_dir)
    : pg_dsn_(pg_dsn) {
    
    pool_ = std::make_unique<PgConnectionPool>(pg_dsn_, 8);
    migration_runner_ = std::make_unique<MigrationRunner>(*pool_);
    
    // Run migrations synchronously on startup
    if (!migration_runner_->run_all()) {
        std::cerr << "[StorageEngine] Warning: Migrations failed. Storage may not work.\n";
    }

    queue_ = std::make_unique<WriteQueue>();
    batch_writer_ = std::make_unique<BatchWriter>(*queue_, *pool_);
    
    pcap_manager_ = std::make_unique<PcapFileManager>(pcap_dir);
    
    // 5 GB quota
    retention_manager_ = std::make_unique<RetentionManager>(pcap_dir, 5ULL * 1024 * 1024 * 1024);
}

StorageEngine::~StorageEngine() {
    stop();
}

void StorageEngine::start() {
    batch_writer_->start();
    pcap_manager_->start();
    retention_manager_->start();
    std::cout << "[StorageEngine] Started batch writer, pcap manager, and retention manager.\n";
}

void StorageEngine::stop() {
    if (batch_writer_) batch_writer_->stop();
    if (pcap_manager_) pcap_manager_->stop();
    if (retention_manager_) retention_manager_->stop();
}

void StorageEngine::write_session_start(std::shared_ptr<SessionStart> session_ptr) {
    auto ev = make_event(EventType::SESSION_STARTED, std::move(session_ptr));
    if (!queue_->push(ev)) {
        delete static_cast<std::shared_ptr<SessionStart>*>(ev.shared_block);
    }
}

void StorageEngine::write_session_end(const std::string& session_id) {
    auto session_ptr = std::make_shared<std::string>(session_id);
    auto ev = make_event(EventType::SESSION_ENDED, std::move(session_ptr));
    if (!queue_->push(ev)) {
        delete static_cast<std::shared_ptr<std::string>*>(ev.shared_block);
    }
}

void StorageEngine::write_flow(std::shared_ptr<Flow> flow_ptr) {
    auto ev = make_event(EventType::FLOW_CLOSED, std::move(flow_ptr));
    if (!queue_->push(ev)) {
        delete static_cast<std::shared_ptr<Flow>*>(ev.shared_block);
    }
}

void StorageEngine::write_alert(std::shared_ptr<Alert> alert_ptr) {
    auto ev = make_event(EventType::ALERT_FIRED, std::move(alert_ptr));
    if (!queue_->push(ev)) {
        delete static_cast<std::shared_ptr<Alert>*>(ev.shared_block);
    }
}

void StorageEngine::write_metrics_snapshot(std::shared_ptr<void> metrics_ptr) {
    // metrics writes aren't wired to batch inserts yet — just release immediately
    // (no-op until BatchWriter::insert_metrics is implemented)
}

void StorageEngine::write_raw_packet(const CapturedPacket& packet) {
    if (pcap_manager_) {
        timespec ts;
        ts.tv_sec  = packet.timestamp.count() / 1000000000LL;
        ts.tv_nsec = packet.timestamp.count() % 1000000000LL;
        pcpp::RawPacket raw_pkt(
            reinterpret_cast<const uint8_t*>(packet.raw.data()),
            static_cast<int>(packet.raw.size()),
            ts,
            false  // do not free buffer — we own it
        );
        pcap_manager_->write_packet(&raw_pkt);
    }
}

nlohmann::json StorageEngine::get_sessions() {
    try {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);
        auto res = tx.exec(
            "SELECT session_id, name, description, start_time, end_time, "
            "interface_name, packets_captured, packets_dropped "
            "FROM capture_sessions ORDER BY start_time DESC"
        );
        nlohmann::json arr = nlohmann::json::array();
        for (auto row : res) {
            nlohmann::json j;
            j["session_id"]       = row[0].is_null() ? "" : row[0].c_str();
            j["name"]             = row[1].is_null() ? "" : row[1].c_str();
            j["description"]      = row[2].is_null() ? "" : row[2].c_str();
            j["start_time"]       = row[3].is_null() ? "" : row[3].c_str();
            if (row[4].is_null()) {
                j["end_time"] = nullptr;
            } else {
                j["end_time"] = row[4].c_str();
            }
            j["interface_name"]   = row[5].is_null() ? "" : row[5].c_str();
            j["packets_captured"] = row[6].as<int64_t>(0);
            j["packets_dropped"]  = row[7].as<int64_t>(0);
            arr.push_back(j);
        }
        return arr;
    } catch (const std::exception& e) {
        return nlohmann::json{{"error", e.what()}};
    }
}

nlohmann::json StorageEngine::query_flows(const std::string& session_id, int limit, int offset) {
    try {
        auto conn = pool_->acquire();
        pqxx::work tx(*conn);
        auto res = tx.exec(
            "SELECT flow_id, src_ip::text, dst_ip::text, src_port, dst_port, "
            "protocol, start_time, end_time, duration_ms, fwd_bytes, rev_bytes "
            "FROM flows WHERE session_id = $1 ORDER BY start_time DESC LIMIT $2 OFFSET $3",
            pqxx::params{session_id, limit, offset}
        );
        nlohmann::json arr = nlohmann::json::array();
        for (auto row : res) {
            nlohmann::json j;
            j["flow_id"]     = row[0].as<int64_t>(0);
            j["src_ip"]      = row[1].c_str();
            j["dst_ip"]      = row[2].c_str();
            j["src_port"]    = row[3].as<int>(0);
            j["dst_port"]    = row[4].as<int>(0);
            j["protocol"]    = row[5].as<int>(0);
            j["start_time"]  = row[6].c_str();
            j["end_time"]    = row[7].c_str();
            j["duration_ms"] = row[8].as<int64_t>(0);
            j["fwd_bytes"]   = row[9].as<int64_t>(0);
            j["rev_bytes"]   = row[10].as<int64_t>(0);
            arr.push_back(j);
        }
        return arr;
    } catch (const std::exception& e) {
        return nlohmann::json{{"error", e.what()}};
    }
}

nlohmann::json StorageEngine::query_metrics_history(const std::string& metric_name,
                                                    const std::string& resolution) {
    return nlohmann::json::array(); // stub — TimescaleDB continuous aggregates TBD
}

nlohmann::json StorageEngine::get_status() {
    return {
        {"queue_capacity", 100000},
        {"queue_size",     queue_->read_available()}
    };
}

} // namespace storage
