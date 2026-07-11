#pragma once
#include "../detector_base.hpp"
#include "../../metrics/http_metrics.hpp"
#include <string>

// ── HttpLatencyDetector ───────────────────────────────────────────────────────
// Fires when HTTP p95 response latency exceeds the adaptive threshold.
// Baseline tracks p50 (normal response time) — adapts to slow backends.
// Default static threshold: 1000ms (1 second p95 response time).

class HttpLatencyDetector : public DetectorBase {
public:
    HttpLatencyDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 1000.0,  // 1s p95
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 120'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const HttpMetrics::Snapshot& snap) {
        double p95 = snap.latency_p95_ms;
        update_baseline(snap.latency_p50_ms);  // baseline on p50

        double thr = effective_threshold();
        if (p95 <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = p95;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        if (!snap.slowest_endpoints.empty()) {
            ctx.endpoint = snap.slowest_endpoints[0].key;
            ctx.extra    = "slowest: " + ctx.endpoint
                         + " avg=" + std::to_string(static_cast<int>(
                             snap.slowest_endpoints[0].avg)) + "ms";
        }

        Alert a;
        a.type      = AlertType::HTTP_LATENCY_SPIKE;
        a.severity  = p95 > 5000.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "HTTP latency spike: p95="
                    + std::to_string(static_cast<int>(p95)) + "ms";
        a.description = "HTTP p95 response time is "
                      + std::to_string(static_cast<int>(p95))
                      + "ms (p50_baseline="
                      + std::to_string(static_cast<int>(ewma_.get()))
                      + "ms). " + ctx.extra;
        a.context = ctx;

        fire(std::move(a), "http_latency");
    }
};
