#pragma once
#include "../detector_base.hpp"
#include "../../metrics/tcp_metrics.hpp"
#include <string>

// ── HighRttDetector ───────────────────────────────────────────────────────────
// Fires when TCP p95 RTT exceeds the adaptive threshold.
// Default static threshold: 200,000 µs = 200ms.
// Severity: WARNING >200ms, CRITICAL >500ms.
// Baseline tracks p95 RTT — high-latency routes naturally have higher baselines.

class HighRttDetector : public DetectorBase {
public:
    HighRttDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 200'000.0,  // 200ms in µs
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 120'000'000'000LL,  // 2 min
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const TcpMetrics::Snapshot& snap) {
        double p95_us = snap.rtt_p95_us;
        update_baseline(snap.rtt_p50_us);  // baseline on p50 (normal), detect on p95

        double thr = effective_threshold();
        if (p95_us <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = p95_us;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        Alert a;
        a.type      = AlertType::TCP_HIGH_RTT;
        a.severity  = p95_us > 500'000.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "High TCP RTT: p95="
                    + std::to_string(static_cast<int>(p95_us / 1000)) + "ms";
        a.description = "TCP p95 RTT is "
                      + std::to_string(static_cast<int>(p95_us / 1000))
                      + "ms (threshold="
                      + std::to_string(static_cast<int>(thr / 1000))
                      + "ms, p50_baseline="
                      + std::to_string(static_cast<int>(ewma_.get() / 1000))
                      + "ms). Users may experience elevated response times.";
        a.context = ctx;

        fire(std::move(a), "tcp_high_rtt");
    }
};
