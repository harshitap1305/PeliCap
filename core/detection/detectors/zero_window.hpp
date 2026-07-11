#pragma once
#include "../detector_base.hpp"
#include "../../metrics/tcp_metrics.hpp"
#include <string>

// ── ZeroWindowDetector ────────────────────────────────────────────────────────
// Fires when the zero-window rate is sustained above the threshold.
// Zero-window events indicate receiver buffer exhaustion — a sign of the
// receiver being overwhelmed or a slow consumer on a fast producer connection.
// Default static threshold: 1.0 (any sustained zero-window activity).

class ZeroWindowDetector : public DetectorBase {
public:
    ZeroWindowDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 1.0,    // any non-trivial rate
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 60'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const TcpMetrics::Snapshot& snap) {
        double rate = snap.zero_window_rate;
        update_baseline(rate);

        double thr = effective_threshold();
        if (rate <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        Alert a;
        a.type      = AlertType::TCP_ZERO_WINDOW;
        a.severity  = rate > thr * 3.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "TCP zero-window events elevated: "
                    + std::to_string(static_cast<int>(rate)) + "/min";
        a.description = "Zero-window rate of "
                      + std::to_string(rate)
                      + " events/min indicates receiver buffer exhaustion. "
                      + "This causes sender pauses and degraded throughput. "
                      + "Check receiving application or system memory pressure.";
        a.context = ctx;

        fire(std::move(a), "tcp_zero_window");
    }
};
