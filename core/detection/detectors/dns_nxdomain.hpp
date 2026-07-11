#pragma once
#include "../detector_base.hpp"
#include "../../metrics/dns_metrics.hpp"
#include <string>

// ── DnsNxdomainDetector ───────────────────────────────────────────────────────
// Fires when NXDOMAIN response rate spikes above the adaptive threshold.
// Elevated NXDOMAIN rate indicates:
//   - Misconfigured applications querying wrong domains
//   - DNS-based malware C2 beaconing (DGA domains)
//   - Deployment pushing queries to a wrong search domain
// Default: 10% static. Higher sigma (4.0) — NXDOMAIN bursts are uncommon.

class DnsNxdomainDetector : public DetectorBase {
public:
    DnsNxdomainDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 10.0,    // 10% NXDOMAIN rate
            .sigma_multiplier     = 4.0,     // higher sigma — NXDOMAIN bursts uncommon
            .cooldown_ns          = 300'000'000'000LL,  // 5 min
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const DnsMetrics::Snapshot& snap) {
        double rate = snap.nxdomain_rate_pct;
        update_baseline(rate);

        double thr = effective_threshold();
        if (rate <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();

        Alert a;
        a.type      = AlertType::DNS_NXDOMAIN_SPIKE;
        a.severity  = rate > 40.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "DNS NXDOMAIN rate elevated: "
                    + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "NXDOMAIN rate of "
                      + std::to_string(rate)
                      + "% (baseline=" + std::to_string(ewma_.get()) + "%). "
                      + "Possible causes: misconfigured clients, DNS-based malware C2 "
                      + "beaconing (DGA domains), or wrong search domain configuration.";
        a.context = ctx;

        fire(std::move(a), "dns_nxdomain");
    }
};
