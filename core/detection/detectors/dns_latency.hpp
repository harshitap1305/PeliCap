#pragma once
#include "../detector_base.hpp"
#include "../../metrics/dns_metrics.hpp"
#include <string>

// ── DnsLatencyDetector ────────────────────────────────────────────────────────
// Fires when DNS p95 resolution latency exceeds the adaptive threshold.
// Baseline tracks average resolution time to adapt to slow upstream resolvers.
// Default static threshold: 500ms (typical upstream recursion, with margin).

class DnsLatencyDetector : public DetectorBase {
public:
    DnsLatencyDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 500.0,   // 500ms p95 static fallback
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 120'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const DnsMetrics::Snapshot& snap) {
        double p95 = static_cast<double>(snap.p95_resolution_ms);
        update_baseline(snap.avg_resolution_ms);  // baseline on avg, detect on p95

        double thr = effective_threshold();
        if (p95 <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = p95;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        if (!snap.slowest_domains.empty()) {
            ctx.domain = snap.slowest_domains[0].key;
            ctx.extra  = "slowest: " + ctx.domain
                       + " avg=" + std::to_string(static_cast<int>(
                           snap.slowest_domains[0].avg)) + "ms";
        }

        Alert a;
        a.type      = AlertType::DNS_HIGH_LATENCY;
        a.severity  = p95 > 1000.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "DNS resolution slow: p95="
                    + std::to_string(static_cast<int>(p95)) + "ms";
        a.description = "DNS p95 latency is "
                      + std::to_string(static_cast<int>(p95))
                      + "ms (avg_baseline="
                      + std::to_string(static_cast<int>(ewma_.get()))
                      + "ms). DNS latency contributes directly to API first-byte time. "
                      + ctx.extra;
        a.context = ctx;

        fire(std::move(a), "dns_latency");
    }
};
