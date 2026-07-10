#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"
#include <string>
#include <cstdint>

// ── HttpMetrics ───────────────────────────────────────────────────────────────
// Tracks HTTP request/response latency, error rates, and top endpoints.
//
// Data is fed by MetricsEngine when it detects the first HTTP response on a
// flow that has http_request_first_seen_ns set (added in Module 4 Phase 1).

class HttpMetrics {
public:
    // Called when an HTTP response is detected on a flow that had a prior request.
    // latency_ms = (response_ts_ns - http_request_first_seen_ns) / 1e6
    void on_http_transaction(const std::string& method,
                             const std::string& url,
                             const std::string& host,
                             int status_code,
                             uint32_t latency_ms,
                             uint64_t response_bytes,
                             int64_t ts_sec) {
        req_rate_.record(1.0, ts_sec);

        if (latency_ms > 0) {
            latency_histogram_.record(latency_ms);
            latency_window_.record(static_cast<double>(latency_ms), ts_sec);
        }

        if (response_bytes > 0)
            bytes_window_.record_bytes(0, response_bytes, ts_sec);

        // Error tracking
        if (status_code >= 400) {
            error_count_.record(1.0, ts_sec);
            if (status_code >= 500)
                server_error_count_.record(1.0, ts_sec);
        }

        // Status code bucket: "2xx", "3xx", "4xx", "5xx"
        if (status_code > 0) {
            std::string bucket = std::to_string(status_code / 100) + "xx";
            status_codes_.increment(bucket);
        }

        // Top endpoints — key = "METHOD /path"
        std::string endpoint = method + " " + (url.empty() ? "/" : url);
        endpoint_counts_.increment(endpoint);
        if (latency_ms > 0)
            slowest_endpoints_.record_latency(endpoint, latency_ms);

        if (!host.empty())
            host_counts_.increment(host);
    }

    struct Snapshot {
        double   req_per_sec      = 0.0;
        double   latency_p50_ms   = 0.0;
        double   latency_p95_ms   = 0.0;
        double   latency_p99_ms   = 0.0;
        double   error_rate_pct   = 0.0;
        double   server_error_pct = 0.0;
        double   bytes_per_sec    = 0.0;
        std::vector<TopNTracker<std::string>::Entry> top_endpoints;
        std::vector<TopNTracker<std::string>::Entry> slowest_endpoints;
        std::vector<TopNTracker<std::string>::Entry> top_hosts;
        std::vector<TopNTracker<std::string>::Entry> status_breakdown;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        size_t w   = std::min(window_sec, size_t(59));
        auto rr    = req_rate_.summarize(w);
        auto err   = error_count_.summarize(w);
        auto serr  = server_error_count_.summarize(w);
        auto byt   = bytes_window_.summarize(w);

        s.req_per_sec      = rr.rate_per_sec;
        s.latency_p50_ms   = latency_histogram_.p50();
        s.latency_p95_ms   = latency_histogram_.p95();
        s.latency_p99_ms   = latency_histogram_.p99();
        s.error_rate_pct   = rr.count > 0
            ? 100.0 * static_cast<double>(err.count) / static_cast<double>(rr.count)
            : 0.0;
        s.server_error_pct = rr.count > 0
            ? 100.0 * static_cast<double>(serr.count) / static_cast<double>(rr.count)
            : 0.0;
        s.bytes_per_sec    = window_sec > 0
            ? static_cast<double>(byt.bytes_out_total) / static_cast<double>(window_sec)
            : 0.0;
        s.top_endpoints    = endpoint_counts_.top_by_count(10);
        s.slowest_endpoints= slowest_endpoints_.top_by_avg_latency(10);
        s.top_hosts        = host_counts_.top_by_count(10);
        s.status_breakdown = status_codes_.top_by_count(6);
        return s;
    }

    void reset_histogram() {
        latency_histogram_.reset();
        endpoint_counts_.reset();
        slowest_endpoints_.reset();
        host_counts_.reset();
    }

private:
    HttpDnsHistogram         latency_histogram_;
    Window1s                 req_rate_{1};
    Window1s                 latency_window_{1};
    Window1s                 error_count_{1};
    Window1s                 server_error_count_{1};
    Window1s                 bytes_window_{1};
    TopNTracker<std::string> endpoint_counts_{1000000};
    TopNTracker<std::string> slowest_endpoints_{1000000};
    TopNTracker<std::string> host_counts_{100000};
    TopNTracker<std::string> status_codes_{10};
};
