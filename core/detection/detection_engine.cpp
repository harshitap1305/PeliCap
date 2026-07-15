#include "detection_engine.hpp"
#include "../metrics/tcp_metrics.hpp"
#include "../metrics/dns_metrics.hpp"
#include "../metrics/http_metrics.hpp"
#include "../metrics/network_metrics.hpp"
#include <fstream>
#include <iostream>
#include <chrono>

// ── Constructor ───────────────────────────────────────────────────────────────
DetectionEngine::DetectionEngine() {
    rexmit_    = std::make_unique<TcpRetransmissionDetector>(store_, cooldown_);
    high_rtt_  = std::make_unique<HighRttDetector>(store_, cooldown_);
    zero_win_  = std::make_unique<ZeroWindowDetector>(store_, cooldown_);
    dns_lat_   = std::make_unique<DnsLatencyDetector>(store_, cooldown_);
    dns_nx_    = std::make_unique<DnsNxdomainDetector>(store_, cooldown_);
    http_err_  = std::make_unique<HttpErrorRateDetector>(store_, cooldown_);
    http_lat_  = std::make_unique<HttpLatencyDetector>(store_, cooldown_);
    traffic_   = std::make_unique<TrafficSpikeDetector>(store_, cooldown_);
    port_scan_ = std::make_unique<PortScanDetector>(store_, cooldown_);
    large_flow_= std::make_unique<LargeFlowDetector>(store_, cooldown_);
}

DetectionEngine::~DetectionEngine() {
    stop();
}

// ── Config loading ────────────────────────────────────────────────────────────
void DetectionEngine::load_config(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[DetectionEngine] Config not found: " << path
                  << " — using defaults\n";
        return;
    }
    try {
        nlohmann::json cfg = nlohmann::json::parse(f);
        auto& d = cfg.at("detectors");

        auto apply = [&](const std::string& key, DetectorBase* det) {
            if (!d.contains(key)) return;
            auto& dc = d.at(key);
            if (dc.contains("enabled"))          det->set_enabled(dc["enabled"].get<bool>());
            if (dc.contains("static_threshold"))  det->set_threshold(dc["static_threshold"].get<double>());
            if (dc.contains("sigma"))             det->set_sigma(dc["sigma"].get<double>());
            if (dc.contains("cooldown_sec"))
                det->set_cooldown_ns(dc["cooldown_sec"].get<int64_t>() * 1'000'000'000LL);
        };

        apply("tcp_retransmission", rexmit_.get());
        apply("high_rtt",           high_rtt_.get());
        apply("zero_window",        zero_win_.get());
        apply("dns_latency",        dns_lat_.get());
        apply("dns_nxdomain",       dns_nx_.get());
        apply("http_error_rate",    http_err_.get());
        apply("http_latency",       http_lat_.get());
        apply("traffic_spike",      traffic_.get());

        // Port scan specific fields
        if (d.contains("port_scan")) {
            auto& ps = d["port_scan"];
            PortScanConfig sc;
            if (ps.contains("ports_per_minute")) sc.ports_per_minute = ps["ports_per_minute"].get<uint32_t>();
            if (ps.contains("hosts_per_minute")) sc.hosts_per_minute = ps["hosts_per_minute"].get<uint32_t>();
            port_scan_ = std::make_unique<PortScanDetector>(store_, cooldown_, sc);
            if (ps.contains("enabled")) port_scan_->set_enabled(ps["enabled"].get<bool>());
        }

        // Large flow specific fields
        if (d.contains("large_flow")) {
            auto& lf = d["large_flow"];
            LargeFlowCfg lc;
            if (lf.contains("bytes_threshold"))  lc.bytes_threshold = lf["bytes_threshold"].get<uint64_t>();
            if (lf.contains("duration_sec"))      lc.duration_threshold_ns = lf["duration_sec"].get<int64_t>() * 1'000'000'000LL;
            large_flow_ = std::make_unique<LargeFlowDetector>(store_, cooldown_, lc);
            if (lf.contains("enabled")) large_flow_->set_enabled(lf["enabled"].get<bool>());
        }

        std::cout << "[DetectionEngine] Config loaded from " << path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[DetectionEngine] Config parse error: " << e.what() << "\n";
    }
}

// ── Baseline persistence ──────────────────────────────────────────────────────
void DetectionEngine::load_baselines(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
    try {
        nlohmann::json j = nlohmann::json::parse(f);
        if (j.contains("rexmit"))    rexmit_->baseline().import_state(j["rexmit"]);
        if (j.contains("high_rtt"))  high_rtt_->baseline().import_state(j["high_rtt"]);
        if (j.contains("zero_win"))  zero_win_->baseline().import_state(j["zero_win"]);
        if (j.contains("dns_lat"))   dns_lat_->baseline().import_state(j["dns_lat"]);
        if (j.contains("dns_nx"))    dns_nx_->baseline().import_state(j["dns_nx"]);
        if (j.contains("http_err"))  http_err_->baseline().import_state(j["http_err"]);
        if (j.contains("http_lat"))  http_lat_->baseline().import_state(j["http_lat"]);
        if (j.contains("traffic"))   traffic_->baseline().import_state(j["traffic"]);
        std::cout << "[DetectionEngine] Baselines restored from " << path << "\n";
    } catch (...) {}
}

void DetectionEngine::save_baselines(const std::string& path) const {
    try {
        nlohmann::json j = {
            {"rexmit",   rexmit_->baseline().export_state()},
            {"high_rtt", high_rtt_->baseline().export_state()},
            {"zero_win", zero_win_->baseline().export_state()},
            {"dns_lat",  dns_lat_->baseline().export_state()},
            {"dns_nx",   dns_nx_->baseline().export_state()},
            {"http_err", http_err_->baseline().export_state()},
            {"http_lat", http_lat_->baseline().export_state()},
            {"traffic",  traffic_->baseline().export_state()}
        };
        std::ofstream f(path);
        f << j.dump(2);
        std::cout << "[DetectionEngine] Baselines saved to " << path << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[DetectionEngine] Failed to save baselines: " << e.what() << "\n";
    }
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────
void DetectionEngine::connect_postgres(const std::string& dsn) {
    if (dsn.empty()) return;
    if (pg_.connect(dsn)) {
        store_.add_callback([this](const Alert& a) {
            pg_.insert_alert(a);
        });
    }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
void DetectionEngine::start(const MetricsEngine& metrics) {
    running_ = true;
    tick_thread_ = std::thread([this, &metrics]() {
        while (running_) {
            std::unique_lock<std::mutex> lk(sleep_mtx_);
            cv_.wait_for(lk, std::chrono::seconds(10), [this] { return !running_.load(); });
            if (running_) tick(metrics);
        }
    });
    std::cout << "[DetectionEngine] Started (10s tick)\n";
}

void DetectionEngine::stop() {
    running_ = false;
    cv_.notify_all();
    if (tick_thread_.joinable()) tick_thread_.join();
}

// ── Tick — metric-based detectors ────────────────────────────────────────────
void DetectionEngine::tick(const MetricsEngine& metrics) {
    TcpMetrics::Snapshot     tcp  = metrics.tcp_snapshot(60);
    DnsMetrics::Snapshot     dns  = metrics.dns_snapshot(60);
    HttpMetrics::Snapshot    http = metrics.http_snapshot(60);
    NetworkMetrics::Snapshot net  = metrics.network_snapshot(60);

    rexmit_ ->evaluate(tcp);
    high_rtt_->evaluate(tcp);
    zero_win_->evaluate(tcp);
    dns_lat_ ->evaluate(dns);
    dns_nx_  ->evaluate(dns);
    http_err_->evaluate(http);
    http_lat_->evaluate(http);
    traffic_ ->evaluate(net);

    // Periodic cooldown eviction (every tick = every 10s)
    cooldown_.evict_old(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// ── FlowEngine event integration ──────────────────────────────────────────────
void DetectionEngine::on_flow_event(FlowEvent event,
                                    std::shared_ptr<Flow> flow) {
    if (!flow) return;

    if (event == FlowEvent::NEW) {
        port_scan_->on_new_flow(
            flow->src_ip_str, flow->dst_ip_str,
            flow->dst_port,   flow->start_time_ns,
            flow->session_id);
    }

    if (event == FlowEvent::CLOSED || event == FlowEvent::EXPIRED) {
        large_flow_->on_flow_closed(*flow);
    }
}

// ── Alert correlation ─────────────────────────────────────────────────────────
// (Called within AlertStore::push via a post-push hook — not currently wired
//  because correlation needs to happen before push; correlation is applied
//  inline in each detector's fire() if needed. This is a placeholder for
//  future inter-detector correlation.)
void DetectionEngine::correlate(Alert& a) {
    if (a.context.dst_ip.empty()) return;
    const int64_t CORR_WINDOW_NS = 5'000'000'000LL;  // 5 seconds

    auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    std::lock_guard<std::mutex> lk(corr_mtx_);
    auto it = last_per_dst_.find(a.context.dst_ip);
    if (it != last_per_dst_.end() && (now - it->second.second) < CORR_WINDOW_NS) {
        a.correlation_id = it->second.first;  // same group as prior alert to this dst
    } else {
        a.correlation_id = next_correlation_id_.fetch_add(1);
        last_per_dst_[a.context.dst_ip] = {a.correlation_id, now};
    }
}

// ── REST: detector status ─────────────────────────────────────────────────────
nlohmann::json DetectionEngine::detector_status() const {
    return {
        {"suppressed",          cooldown_.is_suppressed()},
        {"suppressed_until_ns", cooldown_.suppressed_until_ns()},
        {"alert_count",         store_.count()},
        {"detectors", {
            {"tcp_retransmission", rexmit_->status_json()},
            {"high_rtt",           high_rtt_->status_json()},
            {"zero_window",        zero_win_->status_json()},
            {"dns_latency",        dns_lat_->status_json()},
            {"dns_nxdomain",       dns_nx_->status_json()},
            {"http_error_rate",    http_err_->status_json()},
            {"http_latency",       http_lat_->status_json()},
            {"traffic_spike",      traffic_->status_json()},
            {"port_scan",          port_scan_->status_json()},
            {"large_flow",         large_flow_->status_json()}
        }}
    };
}

// ── REST: runtime threshold override ─────────────────────────────────────────
void DetectionEngine::set_detector_config(const std::string& type_name,
                                          const nlohmann::json& cfg) {
    DetectorBase* det = nullptr;
    if      (type_name == "tcp_retransmission") det = rexmit_.get();
    else if (type_name == "high_rtt")           det = high_rtt_.get();
    else if (type_name == "zero_window")        det = zero_win_.get();
    else if (type_name == "dns_latency")        det = dns_lat_.get();
    else if (type_name == "dns_nxdomain")       det = dns_nx_.get();
    else if (type_name == "http_error_rate")    det = http_err_.get();
    else if (type_name == "http_latency")       det = http_lat_.get();
    else if (type_name == "traffic_spike")      det = traffic_.get();
    else if (type_name == "port_scan")          det = port_scan_.get();
    else if (type_name == "large_flow")         det = large_flow_.get();
    if (!det) return;

    if (cfg.contains("enabled"))          det->set_enabled(cfg["enabled"].get<bool>());
    if (cfg.contains("static_threshold")) det->set_threshold(cfg["static_threshold"].get<double>());
    if (cfg.contains("sigma"))            det->set_sigma(cfg["sigma"].get<double>());
    if (cfg.contains("cooldown_sec"))
        det->set_cooldown_ns(cfg["cooldown_sec"].get<int64_t>() * 1'000'000'000LL);
}
