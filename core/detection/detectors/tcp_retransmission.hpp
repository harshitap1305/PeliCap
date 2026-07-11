#pragma once
#include "../detector_base.hpp"
#include "../../metrics/tcp_metrics.hpp"
#include <string>

// ── TcpRetransmissionDetector ─────────────────────────────────────────────────
// Fires when the retransmission rate (% of packets that are retransmits)
// exceeds the adaptive baseline + N*sigma, or the static fallback threshold.
// Default static threshold: 5% (fires before baseline warms up).
// Cooldown: 60 seconds (prevents spam on sustained congestion).

class TcpRetransmissionDetector : public DetectorBase {
public:
    TcpRetransmissionDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 5.0,    // 5% static fallback
            .sigma_multiplier     = 3.0,
            .cooldown_ns          = 60'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const TcpMetrics::Snapshot& snap) {
        double rate = snap.retransmission_rate_pct;
        update_baseline(rate);

        double thr = effective_threshold();
        if (rate <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        AlertSeverity sev = rate > thr * 2.0
                          ? AlertSeverity::CRITICAL
                          : AlertSeverity::WARNING;

        Alert a;
        a.type        = AlertType::TCP_RETRANSMISSION_SPIKE;
        a.severity    = sev;
        a.title       = "TCP retransmission spike: "
                      + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "Retransmission rate of "
                      + std::to_string(rate) + "% exceeds "
                      + (ewma_.ready() ? "dynamic threshold of " : "static threshold of ")
                      + std::to_string(thr) + "% "
                      + "(baseline=" + std::to_string(ewma_.get()) + "%). "
                      + "Indicates packet loss or network congestion.";
        a.context = ctx;

        fire(std::move(a), "tcp_retransmit");
    }
};
