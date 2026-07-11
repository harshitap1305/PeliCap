#pragma once
#include "../detector_base.hpp"
#include "../../metrics/http_metrics.hpp"
#include <string>

// ── HttpErrorRateDetector ─────────────────────────────────────────────────────
// Fires when HTTP 4xx/5xx error rate exceeds the adaptive threshold.
// Baseline adapts to the application's normal error rate (some apps always
// have a small % of 4xx responses from bots/crawlers — this is normal).
// Default static threshold: 5%.

class HttpErrorRateDetector : public DetectorBase {
public:
    HttpErrorRateDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 5.0,    // 5% error rate
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 60'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const HttpMetrics::Snapshot& snap) {
        double rate = snap.error_rate_pct;
        update_baseline(rate);

        double thr = effective_threshold();
        if (rate <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();
        if (!snap.slowest_endpoints.empty())
            ctx.endpoint = snap.slowest_endpoints[0].key;

        Alert a;
        a.type      = AlertType::HTTP_ERROR_RATE_SPIKE;
        a.severity  = rate > 25.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "HTTP error rate elevated: "
                    + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "HTTP 4xx/5xx error rate of "
                      + std::to_string(rate)
                      + "% exceeds baseline of "
                      + std::to_string(ewma_.get())
                      + "%. Check application logs. "
                      + (ctx.endpoint.empty() ? "" : "Worst endpoint: " + ctx.endpoint);
        a.context = ctx;

        fire(std::move(a), "http_error_rate");
    }
};
