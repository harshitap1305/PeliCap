#pragma once
#include <unordered_map>
#include <mutex>
#include <functional>
#include <string>
#include <cstdint>
#include "../dissector/parsed_packet.hpp"

// ── DnsTransactionTracker ────────────────────────────────────────────────────
// Matches DNS queries to responses by (flow_id, transaction_id) to measure
// DNS resolution latency globally across all flows.
//
// This is separate from the per-flow DnsRttTracker in Flow — that one provides
// per-flow RTT samples; this one feeds the global DnsMetrics sub-engine.
//
// Feeding: called from MetricsEngine::on_flow_event() on UPDATED events that
// carry fresh DNS data, identified by dns_transaction_count changes.

class DnsTransactionTracker {
public:
    using ResolvedCallback = std::function<void(
        const std::string& domain,
        uint32_t latency_ms,
        bool nxdomain,
        int64_t ts_sec)>;

    explicit DnsTransactionTracker(ResolvedCallback cb)
        : callback_(std::move(cb)) {}

    // Called for every DNS packet (query or response) detected on a flow.
    // flow_id + transaction_id uniquely identifies a DNS round-trip.
    void on_dns_packet(uint64_t flow_id, const DnsFields& dns, int64_t ts_ns) {
        std::lock_guard<std::mutex> lk(mtx_);

        // Collision-resistant composite key
        uint64_t key = (flow_id * 65537ULL) ^ static_cast<uint64_t>(dns.transaction_id);

        if (!dns.is_response) {
            // Store pending query
            pending_[key] = { dns.query_name, ts_ns };
            evict_stale(ts_ns);
        } else {
            // Match to a pending query
            auto it = pending_.find(key);
            if (it != pending_.end()) {
                uint32_t latency_ms = static_cast<uint32_t>(
                    (ts_ns - it->second.query_ts_ns) / 1'000'000LL);
                bool nxdomain = (dns.rcode == 3);
                if (callback_)
                    callback_(it->second.query_name, latency_ms, nxdomain,
                              ts_ns / 1'000'000'000LL);
                pending_.erase(it);
            }
        }
    }

    // Remove all pending queries — called on capture restart
    void reset() {
        std::lock_guard<std::mutex> lk(mtx_);
        pending_.clear();
    }

private:
    struct PendingQuery {
        std::string query_name;
        int64_t     query_ts_ns = 0;
    };

    mutable std::mutex mtx_;
    std::unordered_map<uint64_t, PendingQuery> pending_;
    ResolvedCallback callback_;

    // Evict queries older than 5 seconds (server never responded)
    void evict_stale(int64_t now_ns) {
        constexpr int64_t TIMEOUT_NS = 5'000'000'000LL;
        for (auto it = pending_.begin(); it != pending_.end(); ) {
            if (it->second.query_ts_ns < now_ns - TIMEOUT_NS)
                it = pending_.erase(it);
            else
                ++it;
        }
    }
};
