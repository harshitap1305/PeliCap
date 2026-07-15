#pragma once
#include "../detector_base.hpp"
#include "../../flow/flow.hpp"
#include <string>

// ── LargeFlowDetector ─────────────────────────────────────────────────────────
// Behavioral detector — called on FlowEvent::CLOSED or FlowEvent::EXPIRED.
// Fires LARGE_FLOW if a single flow transfers > 100 MB.
// Fires TCP_LONG_LIVED_CONNECTION if a flow stays open > 5 minutes.
// Both are INFO severity — observational, not actionable by themselves.
// Cooldown is per flow_id so each flow only alerts once.

// NOTE: LargeFlowConfig is at file scope (not nested in LargeFlowDetector) to
// avoid GCC CWG-1604: nested struct with default member initializers cannot be
// used as a default argument to a constructor in the same enclosing class body.
struct LargeFlowCfg {
    uint64_t bytes_threshold       = 100'000'000ULL;       // 100 MB
    int64_t  duration_threshold_ns = 300'000'000'000LL;    // 5 min
};

class LargeFlowDetector : public DetectorBase {
public:
    // Keep original name as alias for backwards-compatibility
    using LargeFlowConfig = LargeFlowCfg;

    LargeFlowDetector(AlertStore& store, CooldownTracker& cooldown,
                      LargeFlowCfg cfg = LargeFlowCfg())
        : DetectorBase({
            .enabled     = true,
            .cooldown_ns = 600'000'000'000LL,  // 10 min per-flow
          }, store, cooldown),
          lf_cfg_(cfg) {}

    void on_flow_closed(const Flow& f) {
        if (!config_.enabled) return;

        bool is_large     = f.total_bytes()  >= lf_cfg_.bytes_threshold;
        bool is_longlived = f.duration_ns()  >= lf_cfg_.duration_threshold_ns;

        if (is_large) {
            AlertContext ctx;
            ctx.flow_id        = f.flow_id;
            ctx.src_ip         = f.src_ip_str;
            ctx.dst_ip         = f.dst_ip_str;
            ctx.src_port       = f.src_port;
            ctx.dst_port       = f.dst_port;
            ctx.observed_value = static_cast<double>(f.total_bytes());
            ctx.threshold_value = static_cast<double>(lf_cfg_.bytes_threshold);
            ctx.extra = "sni=" + f.tls_sni
                      + " duration=" + std::to_string(f.duration_ns()/1'000'000'000LL) + "s";

            Alert a;
            a.type      = AlertType::LARGE_FLOW;
            a.severity  = AlertSeverity::INFO;
            a.title     = "Large flow: " + fmt_bytes(f.total_bytes())
                        + " " + f.src_ip_str + " → " + f.dst_ip_str;
            a.description = "Flow " + std::to_string(f.flow_id)
                          + " transferred " + fmt_bytes(f.total_bytes())
                          + " in " + std::to_string(f.duration_ns()/1'000'000'000LL)
                          + "s. Protocol: " + std::to_string(f.protocol)
                          + ". SNI: " + f.tls_sni;
            a.session_id = f.session_id;
            a.context = ctx;
            fire(std::move(a), "large_flow:" + std::to_string(f.flow_id));
        }

        if (is_longlived) {
            AlertContext ctx;
            ctx.flow_id  = f.flow_id;
            ctx.src_ip   = f.src_ip_str;
            ctx.dst_ip   = f.dst_ip_str;
            ctx.src_port = f.src_port;
            ctx.dst_port = f.dst_port;
            ctx.observed_value  = static_cast<double>(f.duration_ns());
            ctx.threshold_value = static_cast<double>(lf_cfg_.duration_threshold_ns);

            Alert a;
            a.type      = AlertType::TCP_LONG_LIVED_CONNECTION;
            a.severity  = AlertSeverity::INFO;
            a.title     = "Long-lived connection: " + f.src_ip_str + " → " + f.dst_ip_str
                        + " (" + std::to_string(f.duration_ns()/60'000'000'000LL) + " min)";
            a.description = "Connection open for "
                          + std::to_string(f.duration_ns()/60'000'000'000LL)
                          + " minutes. May indicate persistent tunnel or slow data leak.";
            a.session_id = f.session_id;
            a.context = ctx;
            fire(std::move(a), "longlived:" + std::to_string(f.flow_id));
        }
    }

private:
    LargeFlowCfg lf_cfg_;

    static std::string fmt_bytes(uint64_t b) {
        if (b > 1'000'000'000ULL) return std::to_string(b/1'000'000'000ULL) + " GB";
        if (b > 1'000'000ULL)     return std::to_string(b/1'000'000ULL) + " MB";
        return std::to_string(b/1000ULL) + " KB";
    }
};
