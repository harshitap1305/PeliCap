#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"
#include <string>
#include <cstdint>

// ── DnsMetrics ────────────────────────────────────────────────────────────────
// Tracks DNS resolution quality: latency, NXDOMAIN rate, query rate,
// top queried domains, and slowest domains.
//
// Data is fed by DnsTransactionTracker when it matches a query to its response.

class DnsMetrics {
public:
    // Called by DnsTransactionTracker when a query+response pair is matched
    void on_dns_resolved(const std::string& domain,
                         uint32_t latency_ms,
                         bool nxdomain,
                         int64_t ts_sec) {
        latency_histogram_.record(latency_ms);
        latency_window_.record(static_cast<double>(latency_ms), ts_sec);
        query_rate_.record(1.0, ts_sec);

        if (nxdomain)
            nxdomain_count_.record(1.0, ts_sec);

        if (!domain.empty()) {
            top_domains_.increment(domain);
            if (latency_ms > 0)
                slowest_domains_.record_latency(domain, latency_ms);
        }
    }

    struct Snapshot {
        double   avg_resolution_ms = 0.0;
        uint32_t p95_resolution_ms = 0;
        uint32_t p99_resolution_ms = 0;
        double   nxdomain_rate_pct = 0.0;
        double   queries_per_sec   = 0.0;
        std::vector<TopNTracker<std::string>::Entry> top_domains;
        std::vector<TopNTracker<std::string>::Entry> slowest_domains;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        size_t w   = std::min(window_sec, size_t(59));
        auto lat   = latency_window_.summarize(w);
        auto nx    = nxdomain_count_.summarize(w);
        auto qr    = query_rate_.summarize(w);

        s.avg_resolution_ms = lat.avg;
        s.p95_resolution_ms = latency_histogram_.p95();
        s.p99_resolution_ms = latency_histogram_.p99();
        s.nxdomain_rate_pct = qr.count > 0
            ? 100.0 * static_cast<double>(nx.count) / static_cast<double>(qr.count)
            : 0.0;
        s.queries_per_sec   = qr.rate_per_sec;
        s.top_domains       = top_domains_.top_by_count(20);
        s.slowest_domains   = slowest_domains_.top_by_avg_latency(10);
        return s;
    }

    void reset_histogram() {
        latency_histogram_.reset();
        top_domains_.reset();
        slowest_domains_.reset();
    }

private:
    HttpDnsHistogram         latency_histogram_;
    Window1s                 latency_window_{1};
    Window1s                 query_rate_{1};
    Window1s                 nxdomain_count_{1};
    TopNTracker<std::string> top_domains_{100000};
    TopNTracker<std::string> slowest_domains_{100000};
};
