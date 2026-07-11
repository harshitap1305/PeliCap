#pragma once
#include "../detector_base.hpp"
#include "../../flow/flow.hpp"
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <string>
#include <limits>

// ── PortScanDetector ──────────────────────────────────────────────────────────
// Behavioral detector — not metric-based.
// Monitors per-source-IP connection patterns.
// PORT_SCAN:  one src contacts ≥20 distinct dst ports within 60s
// HOST_SCAN:  one src contacts ≥15 distinct dst hosts within 60s
// Called on FlowEvent::NEW from DetectionEngine::on_flow_event().

// NOTE: ScanConfig is at file scope (not nested in PortScanDetector) to avoid
// GCC CWG-1604: nested struct with default member initializers cannot be used
// as a default argument to a constructor in the same enclosing class body.
struct PortScanConfig {
    uint32_t ports_per_minute = 20;
    uint32_t hosts_per_minute = 15;
    int64_t  window_ns        = 60'000'000'000LL;
};

class PortScanDetector : public DetectorBase {
public:
    // Keep ScanConfig as a type alias for API backwards-compatibility
    using ScanConfig = PortScanConfig;

    PortScanDetector(AlertStore& store, CooldownTracker& cooldown,
                     PortScanConfig cfg = PortScanConfig())
        : DetectorBase({
            .enabled     = true,
            .cooldown_ns = 300'000'000'000LL,  // 5 min
          }, store, cooldown),
          scan_cfg_(cfg) {}

    void on_new_flow(const std::string& src_ip,
                     const std::string& dst_ip,
                     uint16_t dst_port,
                     int64_t  ts_ns)
    {
        if (!config_.enabled) return;
        std::lock_guard<std::mutex> lk(mtx_);
        evict_stale(ts_ns);

        auto& e = per_src_[src_ip];
        if (e.first_seen_ns == 0) e.first_seen_ns = ts_ns;
        e.last_seen_ns = ts_ns;
        e.dst_ports.insert(dst_port);
        e.dst_hosts.insert(dst_ip);

        // Port scan check
        if (e.dst_ports.size() >= scan_cfg_.ports_per_minute) {
            AlertContext ctx;
            ctx.src_ip          = src_ip;
            ctx.observed_value  = static_cast<double>(e.dst_ports.size());
            ctx.threshold_value = scan_cfg_.ports_per_minute;
            ctx.extra = "ports=" + std::to_string(e.dst_ports.size())
                      + " hosts=" + std::to_string(e.dst_hosts.size());

            Alert a;
            a.type      = AlertType::PORT_SCAN;
            a.severity  = AlertSeverity::CRITICAL;
            a.title     = "Port scan from " + src_ip + ": "
                        + std::to_string(e.dst_ports.size()) + " ports/60s";
            a.description = src_ip + " contacted "
                          + std::to_string(e.dst_ports.size())
                          + " distinct ports in under 60s. "
                          + "Consistent with automated port scanning. " + ctx.extra;
            a.context = ctx;
            fire(std::move(a), "port_scan:" + src_ip);
            e.dst_ports.clear();
        }

        // Host scan check
        if (e.dst_hosts.size() >= scan_cfg_.hosts_per_minute) {
            AlertContext ctx;
            ctx.src_ip          = src_ip;
            ctx.observed_value  = static_cast<double>(e.dst_hosts.size());
            ctx.threshold_value = scan_cfg_.hosts_per_minute;

            Alert a;
            a.type      = AlertType::HOST_SCAN;
            a.severity  = AlertSeverity::CRITICAL;
            a.title     = "Host scan from " + src_ip + ": "
                        + std::to_string(e.dst_hosts.size()) + " hosts/60s";
            a.description = src_ip + " contacted "
                          + std::to_string(e.dst_hosts.size())
                          + " distinct hosts in under 60s. "
                          + "Consistent with network enumeration.";
            a.context = ctx;
            fire(std::move(a), "host_scan:" + src_ip);
            e.dst_hosts.clear();
        }
    }

private:
    struct SrcEntry {
        std::unordered_set<uint16_t>    dst_ports;
        std::unordered_set<std::string> dst_hosts;
        int64_t first_seen_ns = 0;
        int64_t last_seen_ns  = 0;
    };

    mutable std::mutex mtx_;
    std::unordered_map<std::string, SrcEntry> per_src_;
    PortScanConfig scan_cfg_;

    void evict_stale(int64_t now_ns) {
        for (auto it = per_src_.begin(); it != per_src_.end(); ) {
            if (now_ns - it->second.last_seen_ns > scan_cfg_.window_ns)
                it = per_src_.erase(it);
            else
                ++it;
        }
    }
};
