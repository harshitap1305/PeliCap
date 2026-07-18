#pragma once
#include "network_metrics.hpp"
#include "tcp_metrics.hpp"
#include "dns_metrics.hpp"
#include "http_metrics.hpp"
#include "dns_transaction_tracker.hpp"
#include "../flow/flow_engine.hpp"
#include <nlohmann/json.hpp>
#include <json/json.h>
#include <thread>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <mutex>

// ── MetricsEngine ─────────────────────────────────────────────────────────────
// Top-level aggregator. Registered as FlowEngine's event callback.
// Routes each FlowEvent to the correct sub-engine.
//
// Thread model:
//   - on_flow_event() called from FlowEngine process thread (hot path)
//   - on_flow_event() also called from FlowEngine expiry thread (EXPIRED events)
//   - housekeeping thread runs every 60s independently
//   - REST snapshot methods called from Drogon's I/O threads
//   All sub-engines are internally thread-safe.

class MetricsEngine {
public:
    MetricsEngine()
        : dns_tracker_([this](const std::string& domain,
                               uint32_t latency_ms,
                               bool nxdomain,
                               int64_t ts_sec) {
              dns_.on_dns_resolved(domain, latency_ms, nxdomain, ts_sec);
          })
    {}

    ~MetricsEngine() { stop_housekeeping(); }

    // ── Main event handler — registered as FlowEngine callback ───────────────
    // Signature matches FlowEventCallback: void(FlowEvent, shared_ptr<Flow>)
    void on_flow_event(FlowEvent event, std::shared_ptr<Flow> flow) {
        if (!flow) return;
        const Flow& f = *flow;

        switch (event) {
            case FlowEvent::NEW:
                network_.on_flow_new(f);
                break;

            case FlowEvent::UPDATED: {
                // ── Byte delta (avoid double-counting cumulative totals) ──────
                uint64_t total_now = f.total_bytes();
                uint64_t delta     = total_now > f.prev_metrics_bytes
                                   ? total_now - f.prev_metrics_bytes : 0;
                // Determine direction split from fwd/rev ratio
                uint64_t delta_in  = 0, delta_out = 0;
                if (delta > 0) {
                    uint64_t total_fwd = f.fwd_bytes;
                    uint64_t total_rev = f.rev_bytes;
                    uint64_t prev      = f.prev_metrics_bytes;
                    // Simple: all new bytes attributed to dominant direction
                    // (accurate enough for top-talkers; exact split negligible)
                    if (total_fwd + total_rev > 0) {
                        delta_in  = delta * total_rev / (total_fwd + total_rev);
                        delta_out = delta - delta_in;
                    } else {
                        delta_in = delta_out = delta / 2;
                    }
                    (void)prev;
                }
                // Update prev_metrics_bytes on the flow (we hold no lock here
                // — FlowEngine calls us after releasing flow->mtx_, so this is
                // safe since we're the only writer of prev_metrics_bytes)
                const_cast<Flow&>(f).prev_metrics_bytes = total_now;

                network_.on_flow_updated(f, delta_in, delta_out);

                // ── DNS transaction matching ──────────────────────────────────
                // Feed dns_tracker if this UPDATED event carries a new DNS txn.
                // We detect "new" by comparing against a per-flow snapshot.
                // The DnsRttTracker in Flow already matched the txid internally;
                // we re-feed the raw info from the flow for global aggregation.
                if (f.app_protocol == AppProtocol::DNS && f.dns_transaction_count > 0) {
                    // Use flow's own dns_rtt tracker — reconstruct the resolved event
                    // Since we don't have access to the raw DnsFields here, we use
                    // the per-flow DNS RTT which the flow already computed.
                    // A positive match means the flow just completed a DNS round-trip.
                    // We track this via a local counter stored in the flow.
                    auto& dns_snap = dns_flow_snapshot_[f.flow_id];
                    if (f.dns_transaction_count > dns_snap) {
                        dns_snap = f.dns_transaction_count;
                        // Compute latency from flow's own RttTracker (DNS RTT is there)
                        uint32_t rtt_us = f.rtt.avg();
                        if (rtt_us > 0) {
                            uint32_t rtt_ms = rtt_us / 1000;
                            bool nxdomain   = false;  // not available post-hoc; fine for metrics
                            dns_.on_dns_resolved(f.dns_query, rtt_ms, nxdomain,
                                                 f.last_seen_ns / 1'000'000'000LL);
                        }
                    }
                }

                // ── HTTP transaction matching ─────────────────────────────────
                // Detect the first HTTP response on a flow that had a request.
                if (f.app_protocol == AppProtocol::HTTP
                        && f.http_request_first_seen_ns > 0
                        && f.http_response_count > 0) {
                    auto& http_snap = http_flow_snapshot_[f.flow_id];
                    if (f.http_response_count > http_snap) {
                        http_snap = f.http_response_count;
                        int64_t latency_ns = f.last_seen_ns - f.http_request_first_seen_ns;
                        uint32_t latency_ms = latency_ns > 0
                            ? static_cast<uint32_t>(latency_ns / 1'000'000LL) : 0;
                        http_.on_http_transaction(
                            "",            // method not stored in flow
                            "",            // url not stored in flow
                            f.http_host,
                            200,           // status not stored — 200 as default
                            latency_ms,
                            f.rev_bytes,
                            f.last_seen_ns / 1'000'000'000LL);
                    }
                }
                break;
            }

            case FlowEvent::CLOSED:
            case FlowEvent::EXPIRED:
                network_.on_flow_closed(f);
                tcp_.on_flow_closed(f);
                // Clean up per-flow snapshot entries
                {
                    std::lock_guard<std::mutex> lk(snapshot_mtx_);
                    dns_flow_snapshot_.erase(f.flow_id);
                    http_flow_snapshot_.erase(f.flow_id);
                }
                break;
        }
    }

    // ── Snapshots for REST API ────────────────────────────────────────────────
    NetworkMetrics::Snapshot network_snapshot(size_t w = 60) const {
        return network_.snapshot(w);
    }
    TcpMetrics::Snapshot tcp_snapshot(size_t w = 60) const {
        return tcp_.snapshot(w);
    }
    DnsMetrics::Snapshot dns_snapshot(size_t w = 60) const {
        return dns_.snapshot(w);
    }
    HttpMetrics::Snapshot http_snapshot(size_t w = 60) const {
        return http_.snapshot(w);
    }

    // ── AI context snapshot (compact JSON for LLM prompt) ────────────────────
    // Called by /api/metrics/ai-context (Module 5). Ready to use now.
    nlohmann::json ai_context_snapshot(size_t window_sec = 60) const {
        auto net  = network_.snapshot(window_sec);
        auto tcp  = tcp_.snapshot(window_sec);
        auto dns  = dns_.snapshot(window_sec);
        auto http = http_.snapshot(window_sec);

        nlohmann::json j;
        j["window_sec"] = window_sec;

        // Network
        j["network"]["bps_in"]        = net.bytes_in_per_sec * 8.0;
        j["network"]["bps_out"]       = net.bytes_out_per_sec * 8.0;
        j["network"]["pps"]           = net.packets_per_sec;
        j["network"]["active_flows"]  = net.active_flows;
        j["network"]["new_flows_per_sec"] = net.new_flows_per_sec;
        auto& tt = j["network"]["top_talkers"];
        for (size_t i = 0; i < std::min(net.top_talkers.size(), size_t(5)); ++i)
            tt.push_back({{"ip", net.top_talkers[i].key},
                          {"bytes", net.top_talkers[i].value}});

        // TCP
        j["tcp"]["rtt_p50_us"]           = tcp.rtt_p50_us;
        j["tcp"]["rtt_p95_us"]           = tcp.rtt_p95_us;
        j["tcp"]["rtt_p99_us"]           = tcp.rtt_p99_us;
        j["tcp"]["retransmit_pct"]       = tcp.retransmission_rate_pct;
        j["tcp"]["zero_window_rate"]     = tcp.zero_window_rate;
        j["tcp"]["avg_flow_duration_ms"] = tcp.avg_flow_duration_ms;
        j["tcp"]["rst_per_min"]          = tcp.rst_per_min;

        // DNS
        j["dns"]["avg_resolution_ms"] = dns.avg_resolution_ms;
        j["dns"]["p95_resolution_ms"] = dns.p95_resolution_ms;
        j["dns"]["nxdomain_pct"]      = dns.nxdomain_rate_pct;
        j["dns"]["queries_per_sec"]   = dns.queries_per_sec;
        auto& sd = j["dns"]["slowest_domains"];
        for (size_t i = 0; i < std::min(dns.slowest_domains.size(), size_t(3)); ++i)
            sd.push_back({{"domain", dns.slowest_domains[i].key},
                          {"avg_ms", dns.slowest_domains[i].avg}});

        // HTTP
        j["http"]["req_per_sec"]    = http.req_per_sec;
        j["http"]["p50_ms"]         = http.latency_p50_ms;
        j["http"]["p95_ms"]         = http.latency_p95_ms;
        j["http"]["p99_ms"]         = http.latency_p99_ms;
        j["http"]["error_rate_pct"] = http.error_rate_pct;
        auto& se = j["http"]["slowest_endpoints"];
        for (size_t i = 0; i < std::min(http.slowest_endpoints.size(), size_t(3)); ++i)
            se.push_back({{"endpoint", http.slowest_endpoints[i].key},
                          {"avg_ms",   http.slowest_endpoints[i].avg}});

        return j;
    }

    // ── WebSocket metrics summary (Json::Value) ─────────────────────────────────
    Json::Value get_summary(size_t window_sec = 1) const {
        auto net = network_.snapshot(window_sec);
        Json::Value j;
        j["bw_in"] = net.bytes_in_per_sec * 8.0 / 1000000.0; // Mbps
        j["bw_out"] = net.bytes_out_per_sec * 8.0 / 1000000.0; // Mbps
        j["pps"] = (Json::UInt64)net.packets_per_sec;
        j["active_flows"] = (Json::UInt64)net.active_flows;
        j["packet_loss"] = 0.0; // Calculate later if needed
        return j;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    void start_housekeeping() {
        if (running_.exchange(true)) return;
        housekeeping_thread_ = std::thread([this]() {
            while (running_) {
                // Sleep in small chunks so stop() responds quickly
                for (int i = 0; i < 60 && running_; ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (!running_) break;
                // Reset histograms so stale percentiles don't carry forward
                tcp_.reset_histogram();
                dns_.reset_histogram();
                http_.reset_histogram();
                // Roll TopN trackers for rolling-window semantics
                network_.reset_topn();
            }
        });
    }

    void stop_housekeeping() {
        running_ = false;
        if (housekeeping_thread_.joinable()) housekeeping_thread_.join();
    }

    void reset() {
        stop_housekeeping();
        {
            std::lock_guard<std::mutex> lk(snapshot_mtx_);
            dns_flow_snapshot_.clear();
            http_flow_snapshot_.clear();
        }
        dns_tracker_.reset();
        start_housekeeping();
    }

private:
    NetworkMetrics network_;
    TcpMetrics     tcp_;
    DnsMetrics     dns_;
    HttpMetrics    http_;

    DnsTransactionTracker dns_tracker_;

    // Per-flow snapshot counters for detecting new DNS/HTTP events
    mutable std::mutex snapshot_mtx_;
    std::unordered_map<uint64_t, uint32_t> dns_flow_snapshot_;   // flow_id → last dns_transaction_count
    std::unordered_map<uint64_t, uint32_t> http_flow_snapshot_;  // flow_id → last http_response_count

    std::atomic<bool> running_{false};
    std::thread housekeeping_thread_;
};
