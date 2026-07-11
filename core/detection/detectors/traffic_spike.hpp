#pragma once
#include "../detector_base.hpp"
#include "../../metrics/network_metrics.hpp"
#include <string>
#include <cmath>

class TrafficSpikeDetector : public DetectorBase {
public:
    TrafficSpikeDetector(AlertStore& store, CooldownTracker& cooldown)
        : DetectorBase({
            .enabled              = true,
            .static_threshold     = 100'000'000.0,
            .sigma_multiplier     = 4.0,
            .cooldown_ns          = 30'000'000'000LL,
            .use_dynamic_threshold = true
          }, store, cooldown) {}

    void evaluate(const NetworkMetrics::Snapshot& snap) {
        double total_bps = (snap.bytes_in_per_sec + snap.bytes_out_per_sec) * 8.0;
        update_baseline(total_bps);

        // Traffic DROP: sudden silence is also suspicious
        if (ewma_.ready()) {
            double floor = ewma_.get() * 0.10;
            if (total_bps < floor && ewma_.get() > 1'000'000.0) {
                AlertContext ctx;
                ctx.observed_value  = total_bps;
                ctx.threshold_value = floor;
                ctx.baseline_value  = ewma_.get();
                Alert a;
                a.type      = AlertType::TRAFFIC_DROP;
                a.severity  = AlertSeverity::WARNING;
                a.title     = "Traffic drop: " + fmt(total_bps) + " (was " + fmt(ewma_.get()) + ")";
                a.description = "Traffic dropped to " + fmt(total_bps)
                              + ", <10% of baseline " + fmt(ewma_.get())
                              + ". Possible network outage.";
                a.context = ctx;
                fire(std::move(a), "traffic_drop");
            }
        }

        double thr = effective_threshold();
        if (total_bps <= thr) return;

        AlertContext ctx;
        ctx.observed_value  = total_bps;
        ctx.threshold_value = thr;
        ctx.baseline_value  = ewma_.get();
        if (!snap.top_talkers.empty()) ctx.src_ip = snap.top_talkers[0].key;

        Alert a;
        a.type      = AlertType::TRAFFIC_SPIKE;
        a.severity  = total_bps > thr * 3.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "Traffic spike: " + fmt(total_bps);
        a.description = "Traffic at " + fmt(total_bps) + " vs baseline " + fmt(ewma_.get())
                      + ". Top source: " + ctx.src_ip;
        a.context = ctx;
        fire(std::move(a), "traffic_spike");
    }

private:
    static std::string fmt(double bps) {
        if (bps > 1e9) return std::to_string(static_cast<int>(bps/1e9)) + " Gbps";
        if (bps > 1e6) return std::to_string(static_cast<int>(bps/1e6)) + " Mbps";
        return std::to_string(static_cast<int>(bps/1e3)) + " Kbps";
    }
};
