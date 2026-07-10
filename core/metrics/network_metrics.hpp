#pragma once
#include "metric_window.hpp"
#include "topn_tracker.hpp"
#include "../flow/flow.hpp"
#include <atomic>
#include <string>
#include <cstdint>

// ── NetworkMetrics ─────────────────────────────────────────────────────────────
// Tracks raw network throughput, packet rates, flow counts, and top talkers.
// Covers the "Network" sub-engine from the Module 4 spec.

class NetworkMetrics {
public:
    void on_flow_new(const Flow& f) {
        int64_t ts = f.start_time_ns / 1'000'000'000LL;
        new_flows_.record(1.0, ts);
        active_flow_count_.fetch_add(1, std::memory_order_relaxed);

        // Protocol breakdown
        std::string proto =
            f.protocol == 6  ? "TCP"    :
            f.protocol == 17 ? "UDP"    :
            f.protocol == 1  ? "ICMP"   :
            f.protocol == 58 ? "ICMPv6" : "OTHER";
        protocol_counts_.increment(proto);
    }

    // delta_bytes = pkt.captured_len for this single packet (NOT cumulative total)
    void on_flow_updated(const Flow& f, uint64_t delta_bytes_in, uint64_t delta_bytes_out) {
        int64_t ts = f.last_seen_ns / 1'000'000'000LL;
        if (delta_bytes_in > 0 || delta_bytes_out > 0)
            bytes_.record_bytes(delta_bytes_in, delta_bytes_out, ts);
        packets_per_sec_.record(1.0, ts);

        // Top talkers — track by source IP
        if (delta_bytes_in + delta_bytes_out > 0) {
            talker_bytes_.increment(f.src_ip_str, delta_bytes_in + delta_bytes_out);
            dest_bytes_.increment(f.dst_ip_str,   delta_bytes_in + delta_bytes_out);
        }
    }

    void on_flow_closed(const Flow& /*f*/) {
        uint64_t cur = active_flow_count_.load(std::memory_order_relaxed);
        if (cur > 0)
            active_flow_count_.fetch_sub(1, std::memory_order_relaxed);
    }

    struct Snapshot {
        double   bytes_in_per_sec  = 0.0;
        double   bytes_out_per_sec = 0.0;
        double   packets_per_sec   = 0.0;
        double   new_flows_per_sec = 0.0;
        uint64_t active_flows      = 0;
        std::vector<TopNTracker<std::string>::Entry> top_talkers;
        std::vector<TopNTracker<std::string>::Entry> top_destinations;
        std::vector<TopNTracker<std::string>::Entry> protocol_breakdown;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        auto net = bytes_.summarize(std::min(window_sec, size_t(59)));
        auto pkt = packets_per_sec_.summarize(std::min(window_sec, size_t(59)));
        auto nf  = new_flows_.summarize(std::min(window_sec, size_t(59)));

        double elapsed = static_cast<double>(window_sec);
        s.bytes_in_per_sec  = elapsed > 0 ? net.bytes_in_total  / elapsed : 0.0;
        s.bytes_out_per_sec = elapsed > 0 ? net.bytes_out_total / elapsed : 0.0;
        s.packets_per_sec   = pkt.rate_per_sec;
        s.new_flows_per_sec = nf.rate_per_sec;
        s.active_flows      = active_flow_count_.load(std::memory_order_relaxed);
        s.top_talkers       = talker_bytes_.top_by_count(10);
        s.top_destinations  = dest_bytes_.top_by_count(10);
        s.protocol_breakdown= protocol_counts_.top_by_count(10);
        return s;
    }

    // Called by housekeeping to roll TopN windows
    void reset_topn() {
        talker_bytes_.reset();
        dest_bytes_.reset();
        protocol_counts_.reset();
    }

private:
    Window1s bytes_{1};
    Window1s packets_per_sec_{1};
    Window1s new_flows_{1};
    std::atomic<uint64_t> active_flow_count_{0};
    TopNTracker<std::string> talker_bytes_{50000};
    TopNTracker<std::string> dest_bytes_{50000};
    TopNTracker<std::string> protocol_counts_{10};
};
