#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"
#include "../flow/flow.hpp"
#include <cstdint>
#include <string>

// ── TcpMetrics ────────────────────────────────────────────────────────────────
// Tracks TCP connection quality: RTT percentiles, retransmission rate,
// zero-window events, flow duration, RST rate, and worst-RTT flows.
// Only processes flows with protocol == 6 (TCP).
// Called on CLOSED and EXPIRED events (when full flow data is available).

class TcpMetrics {
public:
    void on_flow_closed(const Flow& f) {
        if (f.protocol != 6) return;

        int64_t ts = f.last_seen_ns / 1'000'000'000LL;

        // RTT — add all samples from the flow's RttTracker ring buffer
        for (uint8_t i = 0; i < f.rtt.count; ++i)
            rtt_histogram_.record(f.rtt.samples[i]);

        // Retransmission rate for this flow
        uint64_t total_pkts = f.total_packets();
        if (total_pkts > 0) {
            double rexmit_pct = 100.0 * static_cast<double>(f.retransmit.count)
                                      / static_cast<double>(total_pkts);
            rexmit_rate_.record(rexmit_pct, ts);
        }

        // Zero-window events
        if (f.zero_window_events > 0)
            zero_window_.record(static_cast<double>(f.zero_window_events), ts);

        // Flow duration
        double dur_ms = static_cast<double>(f.duration_ns()) / 1e6;
        if (dur_ms >= 0.0)
            flow_duration_.record(dur_ms, ts);

        // Worst RTT flows — key = "src→dst:port"
        uint32_t avg_rtt = f.rtt.avg();
        if (avg_rtt > 0) {
            std::string key = f.src_ip_str + "\u2192" + f.dst_ip_str
                            + ":" + std::to_string(f.dst_port);
            worst_rtt_flows_.record_latency(key, avg_rtt / 1000.0);  // µs → ms
        }

        // RST rate
        if (f.tcp_state == TcpFlowState::RESET)
            rst_count_.record(1.0, ts);

        // Connection setup time
        if (f.connection_setup_us > 0)
            setup_time_.record(static_cast<double>(f.connection_setup_us) / 1000.0, ts);
    }

    struct Snapshot {
        uint32_t rtt_p50_us              = 0;
        uint32_t rtt_p95_us              = 0;
        uint32_t rtt_p99_us              = 0;
        double   retransmission_rate_pct  = 0.0;
        double   zero_window_rate         = 0.0;
        double   avg_flow_duration_ms     = 0.0;
        double   avg_setup_time_ms        = 0.0;
        double   rst_per_min              = 0.0;
        std::vector<TopNTracker<std::string>::Entry> worst_rtt_flows;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        size_t w = std::min(window_sec, size_t(59));
        s.rtt_p50_us              = rtt_histogram_.p50();
        s.rtt_p95_us              = rtt_histogram_.p95();
        s.rtt_p99_us              = rtt_histogram_.p99();
        s.retransmission_rate_pct = rexmit_rate_.summarize(w).avg;
        s.zero_window_rate        = zero_window_.summarize(w).rate_per_sec;
        s.avg_flow_duration_ms    = flow_duration_.summarize(w).avg;
        s.avg_setup_time_ms       = setup_time_.summarize(w).avg;
        s.rst_per_min             = static_cast<double>(rst_count_.summarize(std::min(size_t(60), size_t(59))).count);
        s.worst_rtt_flows         = worst_rtt_flows_.top_by_avg_latency(10);
        return s;
    }

    // Reset histogram every 60s so stale RTTs don't distort percentiles
    void reset_histogram() {
        rtt_histogram_.reset();
        worst_rtt_flows_.reset();
    }

private:
    RttHistogram rtt_histogram_;
    Window1s     rexmit_rate_{1};
    Window1s     zero_window_{1};
    Window1s     flow_duration_{1};
    Window1s     setup_time_{1};
    Window1s     rst_count_{1};
    TopNTracker<std::string> worst_rtt_flows_{10000};
};
