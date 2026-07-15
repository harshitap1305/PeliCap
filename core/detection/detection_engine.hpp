#pragma once
#include "alert.hpp"
#include "alert_store.hpp"
#include "cooldown_tracker.hpp"
#include "pg_store.hpp"
#include "detectors/tcp_retransmission.hpp"
#include "detectors/high_rtt.hpp"
#include "detectors/zero_window.hpp"
#include "detectors/dns_latency.hpp"
#include "detectors/dns_nxdomain.hpp"
#include "detectors/http_error_rate.hpp"
#include "detectors/http_latency.hpp"
#include "detectors/traffic_spike.hpp"
#include "detectors/port_scan.hpp"
#include "detectors/large_flow.hpp"
#include "../flow/flow_engine.hpp"
#include "../metrics/metrics_engine.hpp"
#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <mutex>
#include <condition_variable>
#include <nlohmann/json.hpp>

// ── DetectionEngine ───────────────────────────────────────────────────────────
// Top-level coordinator for Module 5.
// - Owns AlertStore, CooldownTracker, PgStore, and all 10 detectors.
// - Metric-based detectors: evaluated every 10s by the tick thread.
// - Behavioral detectors: notified on FlowEngine events (NEW/CLOSED/EXPIRED).
// - Alert correlation: if two alerts fire to the same dst within 5s, they
//   share a correlation_id so the UI can group them.
// - Baseline persistence: load on start, save on stop (survives container restart).

class DetectionEngine {
public:
    explicit DetectionEngine();
    ~DetectionEngine();

    // Load config from JSON file (config/detectors.json)
    void load_config(const std::string& path);

    // Load/save EWMA baseline state to/from disk (survives container restart)
    void load_baselines(const std::string& path);
    void save_baselines(const std::string& path) const;

    // Connect to PostgreSQL for alert persistence.
    // Non-fatal: in-memory ring buffer continues if PG unavailable.
    void connect_postgres(const std::string& dsn);

    void start(const MetricsEngine& metrics);
    void stop();

    void set_active_session_id(const std::string& sid) {
        if (rexmit_) rexmit_->set_session_id(sid);
        if (high_rtt_) high_rtt_->set_session_id(sid);
        if (zero_win_) zero_win_->set_session_id(sid);
        if (dns_lat_) dns_lat_->set_session_id(sid);
        if (dns_nx_) dns_nx_->set_session_id(sid);
        if (http_err_) http_err_->set_session_id(sid);
        if (http_lat_) http_lat_->set_session_id(sid);
        if (traffic_) traffic_->set_session_id(sid);
        if (port_scan_) port_scan_->set_session_id(sid);
        if (large_flow_) large_flow_->set_session_id(sid);
    }

    // ── FlowEngine integration ────────────────────────────────────────────────
    // Called from FlowEngine's event callback (may be process or expiry thread).
    void on_flow_event(FlowEvent event, std::shared_ptr<Flow> flow);

    // ── REST API access ───────────────────────────────────────────────────────
    const AlertStore& store() const { return store_; }
    AlertStore& store() { return store_; }

    // Suppress all alerts for duration_sec seconds (maintenance window)
    void suppress(int64_t duration_ns) { cooldown_.suppress(duration_ns); }
    bool is_suppressed() const { return cooldown_.is_suppressed(); }

    // Current config and EWMA baselines for GET /api/detectors
    nlohmann::json detector_status() const;

    // Runtime threshold override from REST API
    void set_detector_config(const std::string& type_name,
                             const nlohmann::json& cfg);

private:
    void tick(const MetricsEngine& metrics);
    void correlate(Alert& a);  // assign correlation_id if related alert exists

    AlertStore      store_{10000};
    CooldownTracker cooldown_{60'000'000'000LL};
    PgStore         pg_;

    std::unique_ptr<TcpRetransmissionDetector> rexmit_;
    std::unique_ptr<HighRttDetector>           high_rtt_;
    std::unique_ptr<ZeroWindowDetector>        zero_win_;
    std::unique_ptr<DnsLatencyDetector>        dns_lat_;
    std::unique_ptr<DnsNxdomainDetector>       dns_nx_;
    std::unique_ptr<HttpErrorRateDetector>     http_err_;
    std::unique_ptr<HttpLatencyDetector>       http_lat_;
    std::unique_ptr<TrafficSpikeDetector>      traffic_;
    std::unique_ptr<PortScanDetector>          port_scan_;
    std::unique_ptr<LargeFlowDetector>         large_flow_;

    std::atomic<bool> running_{false};
    std::thread       tick_thread_;
    std::mutex              sleep_mtx_;
    std::condition_variable cv_;

    // Correlation: track last alert per dst_ip and its timestamp
    mutable std::mutex               corr_mtx_;
    std::unordered_map<std::string, std::pair<uint64_t, int64_t>> last_per_dst_;
    std::atomic<uint64_t> next_correlation_id_{1};
};
