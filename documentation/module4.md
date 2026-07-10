Three diagrams for Module 4 — the overall architecture, the time-window mechanics, and the metric taxonomy. Then full implementation.Now the time-window mechanics — understanding this is what separates a toy metrics engine from a production one:Now the complete metric taxonomy — every metric you need to compute and why:Now the full implementation plan.

FlowEvent bus (from Module 3)
MetricsEngine dispatcher
routes FLOW_NEW / UPDATED / CLOSED / EXPIRED to sub-engines
Network
bps, pps, flows
top talkers
TCP quality
RTT, rexmit rate
zero-window events
DNS
latency, NXDOMAIN
top domains
HTTP
p50/p95/p99
error rate
Time-window aggregator
1 s · 10 s · 1 min · 5 min · 1 hr buckets — sliding + tumbling
MetricsStore
in-memory ring buffers per metric · snapshot to PostgreSQL every 60 s
REST API / Dashboard
AI Copilot context builde
Now the time-window mechanics — understanding this is what separates a toy metrics engine from a production one:

Tumbling windows — counters (bytes, packets, new flows)
t=0..1s
bucket 1
t=1..2s
bucket 2
t=2..3s
bucket 3
t=3..4s
current
→ time
Sliding windows — averages (RTT, latency, throughput)
W[-2]
W[-1]
W[now] — last 60 s
now
Ring buffer storage — one per metric per window size
slot 0
t=now-5m
slot 1
t=now-4m
slot 2
t=now-3m
slot 3
t=now-2m
slot 4
t=now-1m
slot 5
current
head (wraps to slot 0 next)
Each slot contains
bytes_in · bytes_out · packet_count · flow_count · rtt_sum · rtt_count · error_count · timestamp
Reading last N slots = last N minutes of data with zero extra allocation
Now the complete metric taxonomy — every metric you need to compute and why:
Network sub-engine
bytes_in_per_sec, bytes_out_per_sec
packets_per_sec (pps)
active_flow_count
new_flows_per_sec
top_talkers[src_ip → bytes]
top_destinations[dst_ip → bytes]
per_protocol_breakdown
TCP quality sub-engine
rtt_p50_us, rtt_p95_us, rtt_p99_us
retransmission_rate (%)
zero_window_rate
connection_setup_time_ms
avg_flow_duration_ms
rst_rate (resets per min)
worst_rtt_flows[top 10]
DNS sub-engine
avg_resolution_time_ms
p95_resolution_time_ms
nxdomain_rate (%)
query_rate (qps)
top_queried_domains[top 20]
slowest_domains[top 10]
HTTP sub-engine
req_per_sec, resp_per_sec
latency_p50/p95/p99_ms
error_rate (4xx+5xx %)
top_endpoints[url → req count]
slowest_endpoints[top 10]
status_code_breakdown
AI context snapshot (generated on demand)
serializes last 60 s of all sub-engines into compact JSON for LLM prompt
never sends raw packets — only aggregated numbers
REST endpoints
GET /metrics/network · /metrics/tcp · /metrics/dns · /metrics/http
GET /metrics/summary?window=60s · /metrics/top-talkers · /metrics/ai-contex
---

## The core design decision: in-memory ring buffers, not a time-series database

The tempting wrong answer is to write every metric to InfluxDB or TimescaleDB in real time. The problems:

- Every packet triggers a write — at 100k pps that's 100k DB writes/sec
- You introduce a network hop on the critical path
- Queries for "last 60 seconds" do full table scans unless you tune indexes carefully

The right answer for a production system at this scale: compute everything in memory using ring buffers, and only flush snapshots to PostgreSQL every 60 seconds for long-term storage. Your dashboard's real-time view reads from memory in microseconds. Historical charts read from PostgreSQL.

---

## The fundamental data structure: `MetricWindow<T>`

Every metric — whether it's bytes per second, RTT, DNS latency, or HTTP error rate — uses the same ring buffer template. Build it once, use it everywhere.

```cpp
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>
#include <algorithm>
#include <numeric>

// One time-bucket of raw accumulated values
struct MetricBucket {
    int64_t  timestamp_sec = 0;   // unix timestamp of bucket start
    uint64_t count         = 0;   // number of samples
    double   sum           = 0.0; // sum of values (for avg)
    double   min           = std::numeric_limits<double>::max();
    double   max           = std::numeric_limits<double>::lowest();
    uint64_t bytes_in      = 0;   // for network metrics
    uint64_t bytes_out     = 0;
    uint64_t errors        = 0;   // for HTTP/DNS error counts

    void reset(int64_t ts) {
        timestamp_sec = ts;
        count = 0; sum = 0.0; errors = 0; bytes_in = 0; bytes_out = 0;
        min = std::numeric_limits<double>::max();
        max = std::numeric_limits<double>::lowest();
    }

    void add_sample(double v) {
        ++count;
        sum += v;
        min = std::min(min, v);
        max = std::max(max, v);
    }

    double avg() const { return count ? sum / count : 0.0; }
};

// Ring buffer of N buckets, each covering `bucket_width_sec` seconds
template<size_t N>
class MetricWindow {
public:
    explicit MetricWindow(int64_t bucket_width_sec = 1)
        : bucket_width_(bucket_width_sec)
    {
        int64_t now = current_sec();
        for (size_t i = 0; i < N; ++i)
            buckets_[i].reset(now - static_cast<int64_t>(N - i) * bucket_width_);
    }

    // Called on every event — thread-safe
    void record(double value, int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard lock(mtx_);
        advance_to(ts_sec);
        current().add_sample(value);
    }

    void record_bytes(uint64_t in, uint64_t out, int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard lock(mtx_);
        advance_to(ts_sec);
        current().bytes_in  += in;
        current().bytes_out += out;
        ++current().count;
    }

    void record_error(int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard lock(mtx_);
        advance_to(ts_sec);
        ++current().errors;
        ++current().count;
    }

    // Read last `n_buckets` completed buckets (not the current one)
    std::vector<MetricBucket> last(size_t n_buckets) const {
        std::lock_guard lock(mtx_);
        n_buckets = std::min(n_buckets, N - 1); // exclude current
        std::vector<MetricBucket> result;
        result.reserve(n_buckets);
        for (size_t i = n_buckets; i >= 1; --i) {
            size_t idx = (head_ + N - i) % N;
            result.push_back(buckets_[idx]);
        }
        return result;
    }

    // Aggregate summary over last n_buckets
    struct Summary {
        double   avg   = 0.0;
        double   min   = 0.0;
        double   max   = 0.0;
        uint64_t count = 0;
        uint64_t bytes_in_total  = 0;
        uint64_t bytes_out_total = 0;
        uint64_t errors_total    = 0;
        double   rate_per_sec    = 0.0;  // count / elapsed_sec
    };

    Summary summarize(size_t n_buckets) const {
        auto buckets = last(n_buckets);
        Summary s;
        s.min = std::numeric_limits<double>::max();
        double sum = 0.0;
        for (auto& b : buckets) {
            s.count          += b.count;
            s.bytes_in_total += b.bytes_in;
            s.bytes_out_total+= b.bytes_out;
            s.errors_total   += b.errors;
            if (b.count) {
                sum  += b.sum;
                s.min = std::min(s.min, b.min);
                s.max = std::max(s.max, b.max);
            }
        }
        if (s.count) s.avg = sum / s.count;
        double elapsed = static_cast<double>(buckets.size()) * bucket_width_;
        if (elapsed > 0) s.rate_per_sec = s.count / elapsed;
        return s;
    }

private:
    mutable std::mutex mtx_;
    std::array<MetricBucket, N> buckets_{};
    size_t  head_         = 0;
    int64_t bucket_width_ = 1;

    MetricBucket& current() { return buckets_[head_]; }

    void advance_to(int64_t ts_sec) {
        int64_t current_bucket_start = buckets_[head_].timestamp_sec;
        int64_t buckets_to_advance   = (ts_sec - current_bucket_start) / bucket_width_;
        if (buckets_to_advance <= 0) return;

        // Advance, zeroing skipped buckets (gaps in traffic)
        for (int64_t i = 0; i < std::min(buckets_to_advance, static_cast<int64_t>(N)); ++i) {
            head_ = (head_ + 1) % N;
            buckets_[head_].reset(current_bucket_start + (i + 1) * bucket_width_);
        }
    }

    static int64_t current_sec() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

// Convenience type aliases — each covers a different time horizon
using Window1s   = MetricWindow<60>;    // 60 × 1s  = last 60 seconds
using Window10s  = MetricWindow<36>;    // 36 × 10s = last 6 minutes
using Window1min = MetricWindow<60>;    // 60 × 1m  = last hour
using Window1hr  = MetricWindow<24>;    // 24 × 1h  = last day
```

---

## The TopN tracker — for top talkers, top domains, top endpoints

This is one of the most practically useful structures in the whole engine. You need the top 10 IPs by bytes, top 20 DNS domains, top 10 slowest HTTP endpoints — updated every second, without sorting a million-entry map.

```cpp
#pragma once
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <string>
#include <mutex>

template<typename Key>
class TopNTracker {
public:
    struct Entry {
        Key      key;
        uint64_t value = 0;
        double   avg   = 0.0;  // for latency-based top-N
        uint64_t count = 0;
    };

    explicit TopNTracker(size_t max_keys = 10000) : max_keys_(max_keys) {}

    void increment(const Key& key, uint64_t delta = 1) {
        std::lock_guard lock(mtx_);
        auto& v = counts_[key];
        v += delta;
        // Evict oldest if map grows too large — prevents unbounded growth
        if (counts_.size() > max_keys_) evict_bottom_10pct();
    }

    void record_latency(const Key& key, double latency_ms) {
        std::lock_guard lock(mtx_);
        auto& e = latencies_[key];
        e.sum   += latency_ms;
        e.count += 1;
    }

    // Get top N by byte/count value
    std::vector<Entry> top_by_count(size_t n) const {
        std::lock_guard lock(mtx_);
        std::vector<Entry> result;
        result.reserve(counts_.size());
        for (auto& [k, v] : counts_)
            result.push_back({k, v, 0.0, v});
        std::partial_sort(result.begin(),
                          result.begin() + std::min(n, result.size()),
                          result.end(),
                          [](const Entry& a, const Entry& b){ return a.value > b.value; });
        result.resize(std::min(n, result.size()));
        return result;
    }

    // Get top N by average latency
    std::vector<Entry> top_by_avg_latency(size_t n) const {
        std::lock_guard lock(mtx_);
        std::vector<Entry> result;
        for (auto& [k, e] : latencies_) {
            double avg = e.count ? e.sum / e.count : 0.0;
            result.push_back({k, e.count, avg, e.count});
        }
        std::partial_sort(result.begin(),
                          result.begin() + std::min(n, result.size()),
                          result.end(),
                          [](const Entry& a, const Entry& b){ return a.avg > b.avg; });
        result.resize(std::min(n, result.size()));
        return result;
    }

    // Reset every minute — prevents stale data from dominating
    void reset() {
        std::lock_guard lock(mtx_);
        counts_.clear();
        latencies_.clear();
    }

private:
    struct LatencyAccum { double sum = 0.0; uint64_t count = 0; };

    mutable std::mutex mtx_;
    std::unordered_map<Key, uint64_t>       counts_;
    std::unordered_map<Key, LatencyAccum>   latencies_;
    size_t max_keys_;

    void evict_bottom_10pct() {
        // Find the 10th percentile threshold and erase everything below it
        std::vector<uint64_t> vals;
        vals.reserve(counts_.size());
        for (auto& [k, v] : counts_) vals.push_back(v);
        std::nth_element(vals.begin(), vals.begin() + vals.size()/10, vals.end());
        uint64_t threshold = vals[vals.size()/10];
        for (auto it = counts_.begin(); it != counts_.end(); ) {
            if (it->second <= threshold) it = counts_.erase(it);
            else ++it;
        }
    }
};
```

---

## The percentile estimator — p50/p95/p99 without storing all samples

For RTT, DNS latency, and HTTP response times you need percentiles, not just averages. The naive approach (store every sample, sort) doesn't scale. Use a t-digest or HDR histogram. For a production-grade but simple implementation, use a fixed-bucket histogram:

```cpp
#pragma once
#include <array>
#include <cstdint>
#include <mutex>

// Fixed-range histogram for latency in microseconds
// Buckets: 0-100us, 100-200us, ..., 9900-10000us, >10ms (overflow)
// Total: 101 buckets covering 0 to 10ms with 100us resolution
class LatencyHistogram {
public:
    static constexpr size_t NUM_BUCKETS = 101;
    static constexpr uint32_t BUCKET_WIDTH_US = 100;   // 100 microseconds per bucket
    static constexpr uint32_t MAX_US = NUM_BUCKETS * BUCKET_WIDTH_US; // 10,100 us = ~10ms

    void record(uint32_t latency_us) {
        std::lock_guard lock(mtx_);
        size_t idx = std::min(latency_us / BUCKET_WIDTH_US,
                              static_cast<uint32_t>(NUM_BUCKETS - 1));
        ++buckets_[idx];
        ++total_;
    }

    // Returns latency at given percentile (0.0–1.0)
    uint32_t percentile(double p) const {
        std::lock_guard lock(mtx_);
        if (!total_) return 0;
        uint64_t target = static_cast<uint64_t>(total_ * p);
        uint64_t cumulative = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            cumulative += buckets_[i];
            if (cumulative >= target)
                return static_cast<uint32_t>(i * BUCKET_WIDTH_US);
        }
        return MAX_US;
    }

    uint32_t p50() const { return percentile(0.50); }
    uint32_t p95() const { return percentile(0.95); }
    uint32_t p99() const { return percentile(0.99); }

    void reset() {
        std::lock_guard lock(mtx_);
        buckets_.fill(0);
        total_ = 0;
    }

    uint64_t count() const {
        std::lock_guard lock(mtx_);
        return total_;
    }

private:
    mutable std::mutex mtx_;
    std::array<uint64_t, NUM_BUCKETS> buckets_{};
    uint64_t total_ = 0;
};
```

For DNS and HTTP latency (which can span hundreds of milliseconds), use a second histogram with wider buckets — 1ms resolution up to 30 seconds.

---

## The four sub-engines — complete implementation

### NetworkMetrics

```cpp
#pragma once
#include "metric_window.hpp"
#include "topn_tracker.hpp"
#include "../flow/flow.hpp"

class NetworkMetrics {
public:
    void on_flow_updated(const Flow& f, uint64_t new_bytes_in, uint64_t new_bytes_out) {
        int64_t ts = f.last_seen_ns / 1'000'000'000LL;
        bytes_.record_bytes(new_bytes_in, new_bytes_out, ts);
        packets_per_sec_.record(1.0, ts);

        // Update top talkers — use source IP as key
        talker_bytes_.increment(f.src_ip_str, new_bytes_in + new_bytes_out);
        dest_bytes_.increment(f.dst_ip_str,   new_bytes_in + new_bytes_out);
    }

    void on_flow_new(const Flow& f) {
        new_flows_.record(1.0, f.start_time_ns / 1'000'000'000LL);
        active_flow_count_.fetch_add(1, std::memory_order_relaxed);
        protocol_counts_.increment(std::to_string(f.protocol));
    }

    void on_flow_closed(const Flow& f) {
        active_flow_count_.fetch_sub(1, std::memory_order_relaxed);
    }

    struct Snapshot {
        double   bytes_in_per_sec  = 0;
        double   bytes_out_per_sec = 0;
        double   packets_per_sec   = 0;
        double   new_flows_per_sec = 0;
        uint64_t active_flows      = 0;
        std::vector<TopNTracker<std::string>::Entry> top_talkers;
        std::vector<TopNTracker<std::string>::Entry> top_destinations;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        size_t n = window_sec; // Window1s has 1s buckets
        auto net = bytes_.summarize(n);
        auto pkt = packets_per_sec_.summarize(n);
        auto nf  = new_flows_.summarize(n);
        s.bytes_in_per_sec  = net.bytes_in_total  / static_cast<double>(window_sec);
        s.bytes_out_per_sec = net.bytes_out_total / static_cast<double>(window_sec);
        s.packets_per_sec   = pkt.rate_per_sec;
        s.new_flows_per_sec = nf.rate_per_sec;
        s.active_flows      = active_flow_count_.load();
        s.top_talkers       = talker_bytes_.top_by_count(10);
        s.top_destinations  = dest_bytes_.top_by_count(10);
        return s;
    }

private:
    Window1s   bytes_{1};
    Window1s   packets_per_sec_{1};
    Window1s   new_flows_{1};
    std::atomic<uint64_t> active_flow_count_{0};
    TopNTracker<std::string> talker_bytes_{50000};
    TopNTracker<std::string> dest_bytes_{50000};
    TopNTracker<std::string> protocol_counts_{100};
};
```

### TcpMetrics

```cpp
#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"

class TcpMetrics {
public:
    void on_flow_closed(const Flow& f) {
        if (f.protocol != 6) return;  // TCP only

        int64_t ts = f.last_seen_ns / 1'000'000'000LL;

        // RTT — record each sample from the flow's ring buffer
        for (uint8_t i = 0; i < f.rtt.count; ++i)
            rtt_histogram_.record(f.rtt.samples[i]);

        // Retransmission rate for this flow
        if (f.total_packets() > 0) {
            double rexmit_pct = 100.0 * f.retransmit.retransmit_count
                                      / f.total_packets();
            rexmit_rate_.record(rexmit_pct, ts);
        }

        // Zero window events
        if (f.zero_window_events > 0)
            zero_window_.record(f.zero_window_events, ts);

        // Connection setup time: INIT→ESTABLISHED duration
        // Approximated as time of first ACK after SYN-ACK
        // Store in flow as setup_time_ns in Module 3 update
        flow_duration_.record(
            static_cast<double>(f.duration_ns()) / 1e6, ts); // ms

        // Track worst flows for the "worst RTT flows" list
        if (f.rtt.avg() > 0)
            worst_rtt_flows_.record_latency(
                f.src_ip_str + "→" + f.dst_ip_str,
                f.rtt.avg() / 1000.0);  // convert us → ms

        // RST tracking
        if (f.tcp_state == TcpFlowState::RESET)
            rst_count_.record(1.0, ts);
    }

    struct Snapshot {
        uint32_t rtt_p50_us = 0, rtt_p95_us = 0, rtt_p99_us = 0;
        double   retransmission_rate_pct = 0;
        double   zero_window_rate        = 0;
        double   avg_flow_duration_ms    = 0;
        double   rst_per_min             = 0;
        std::vector<TopNTracker<std::string>::Entry> worst_rtt_flows;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        s.rtt_p50_us              = rtt_histogram_.p50();
        s.rtt_p95_us              = rtt_histogram_.p95();
        s.rtt_p99_us              = rtt_histogram_.p99();
        s.retransmission_rate_pct = rexmit_rate_.summarize(window_sec).avg;
        s.zero_window_rate        = zero_window_.summarize(window_sec).rate_per_sec;
        s.avg_flow_duration_ms    = flow_duration_.summarize(window_sec).avg;
        s.rst_per_min             = rst_count_.summarize(60).count;
        s.worst_rtt_flows         = worst_rtt_flows_.top_by_avg_latency(10);
        return s;
    }

    // Called once per minute to reset histogram (prevent stale percentiles)
    void reset_histogram() { rtt_histogram_.reset(); }

private:
    LatencyHistogram rtt_histogram_;
    Window1s  rexmit_rate_{1};
    Window1s  zero_window_{1};
    Window1s  flow_duration_{1};
    Window1s  rst_count_{1};
    TopNTracker<std::string> worst_rtt_flows_{10000};
};
```

### DnsMetrics

```cpp
#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"

// DNS latency histogram — wider range, 1ms resolution up to 5s
class DnsLatencyHistogram {
public:
    static constexpr size_t BUCKETS = 500;     // 500 × 10ms = 5 seconds
    static constexpr uint32_t WIDTH_MS = 10;

    void record(uint32_t latency_ms) {
        std::lock_guard lock(mtx_);
        size_t idx = std::min(latency_ms / WIDTH_MS, BUCKETS - 1);
        ++buckets_[idx]; ++total_;
    }
    uint32_t p95() const { return percentile(0.95); }
    uint32_t p99() const { return percentile(0.99); }
    void reset() { std::lock_guard lock(mtx_); buckets_.fill(0); total_ = 0; }

private:
    mutable std::mutex mtx_;
    std::array<uint64_t, BUCKETS> buckets_{};
    uint64_t total_ = 0;
    uint32_t percentile(double p) const {
        uint64_t target = static_cast<uint64_t>(total_ * p), cum = 0;
        for (size_t i = 0; i < BUCKETS; ++i) {
            cum += buckets_[i];
            if (cum >= target) return static_cast<uint32_t>(i * WIDTH_MS);
        }
        return BUCKETS * WIDTH_MS;
    }
};

class DnsMetrics {
public:
    // Called when a DNS request+response pair is matched
    // (matching happens in the flow: same transaction_id, query=request, is_response=true)
    void on_dns_resolved(const std::string& domain, uint32_t latency_ms,
                         bool nxdomain, int64_t ts_sec) {
        latency_histogram_.record(latency_ms);
        latency_window_.record(latency_ms, ts_sec);
        query_rate_.record(1.0, ts_sec);

        if (nxdomain) nxdomain_count_.record(1.0, ts_sec);

        top_domains_.increment(domain);
        if (latency_ms > 0)
            slowest_domains_.record_latency(domain, latency_ms);
    }

    struct Snapshot {
        double   avg_resolution_ms  = 0;
        uint32_t p95_resolution_ms  = 0;
        uint32_t p99_resolution_ms  = 0;
        double   nxdomain_rate_pct  = 0;
        double   queries_per_sec    = 0;
        std::vector<TopNTracker<std::string>::Entry> top_domains;
        std::vector<TopNTracker<std::string>::Entry> slowest_domains;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        auto lat = latency_window_.summarize(window_sec);
        auto nx  = nxdomain_count_.summarize(window_sec);
        auto qr  = query_rate_.summarize(window_sec);
        s.avg_resolution_ms = lat.avg;
        s.p95_resolution_ms = latency_histogram_.p95();
        s.p99_resolution_ms = latency_histogram_.p99();
        s.nxdomain_rate_pct = qr.count > 0
            ? 100.0 * nx.count / qr.count : 0.0;
        s.queries_per_sec   = qr.rate_per_sec;
        s.top_domains       = top_domains_.top_by_count(20);
        s.slowest_domains   = slowest_domains_.top_by_avg_latency(10);
        return s;
    }

    void reset_histogram() { latency_histogram_.reset(); }

private:
    DnsLatencyHistogram              latency_histogram_;
    Window1s                         latency_window_{1};
    Window1s                         query_rate_{1};
    Window1s                         nxdomain_count_{1};
    TopNTracker<std::string>         top_domains_{100000};
    TopNTracker<std::string>         slowest_domains_{100000};
};
```

### HttpMetrics

```cpp
#pragma once
#include "metric_window.hpp"
#include "latency_histogram.hpp"
#include "topn_tracker.hpp"

class HttpMetrics {
public:
    // Called when an HTTP response is matched to its request (by flow)
    // latency_ms = time from request first packet to response last packet
    void on_http_transaction(const std::string& method,
                             const std::string& url,
                             const std::string& host,
                             int status_code,
                             uint32_t latency_ms,
                             uint64_t response_bytes,
                             int64_t ts_sec)
    {
        req_rate_.record(1.0, ts_sec);
        latency_window_.record(latency_ms, ts_sec);
        latency_histogram_.record(latency_ms * 1000); // convert ms→us for histogram

        bytes_window_.record_bytes(0, response_bytes, ts_sec);

        // Error tracking
        if (status_code >= 400) {
            error_count_.record(1.0, ts_sec);
            if (status_code >= 500)
                server_error_count_.record(1.0, ts_sec);
        }

        // Status code breakdown
        std::string bucket = std::to_string(status_code / 100) + "xx";
        status_codes_.increment(bucket);

        // Top endpoints — key = "METHOD /path"
        std::string endpoint = method + " " + url;
        endpoint_counts_.increment(endpoint);
        if (latency_ms > 0)
            slowest_endpoints_.record_latency(endpoint, latency_ms);
        host_counts_.increment(host);
    }

    struct Snapshot {
        double   req_per_sec         = 0;
        double   latency_p50_ms      = 0;
        double   latency_p95_ms      = 0;
        double   latency_p99_ms      = 0;
        double   error_rate_pct      = 0;
        double   server_error_pct    = 0;
        double   bytes_per_sec       = 0;
        std::vector<TopNTracker<std::string>::Entry> top_endpoints;
        std::vector<TopNTracker<std::string>::Entry> slowest_endpoints;
        std::vector<TopNTracker<std::string>::Entry> top_hosts;
        std::vector<TopNTracker<std::string>::Entry> status_breakdown;
    };

    Snapshot snapshot(size_t window_sec = 60) const {
        Snapshot s;
        auto rr  = req_rate_.summarize(window_sec);
        auto err = error_count_.summarize(window_sec);
        auto byt = bytes_window_.summarize(window_sec);
        s.req_per_sec      = rr.rate_per_sec;
        s.latency_p50_ms   = latency_histogram_.p50() / 1000.0;
        s.latency_p95_ms   = latency_histogram_.p95() / 1000.0;
        s.latency_p99_ms   = latency_histogram_.p99() / 1000.0;
        s.error_rate_pct   = rr.count > 0 ? 100.0 * err.count / rr.count : 0.0;
        s.bytes_per_sec    = byt.bytes_out_total / static_cast<double>(window_sec);
        s.top_endpoints    = endpoint_counts_.top_by_count(10);
        s.slowest_endpoints= slowest_endpoints_.top_by_avg_latency(10);
        s.top_hosts        = host_counts_.top_by_count(10);
        s.status_breakdown = status_codes_.top_by_count(10);
        return s;
    }

    void reset_histogram() { latency_histogram_.reset(); }

private:
    LatencyHistogram         latency_histogram_;
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
```

---

## The MetricsEngine — wires everything together

```cpp
#pragma once
#include "network_metrics.hpp"
#include "tcp_metrics.hpp"
#include "dns_metrics.hpp"
#include "http_metrics.hpp"
#include "../flow/flow_engine.hpp"
#include <nlohmann/json.hpp>
#include <thread>
#include <atomic>

class MetricsEngine {
public:
    // This is the single callback you register with FlowEngine
    void on_flow_event(const FlowEventData& ev) {
        const Flow& f = *ev.flow;
        switch (ev.event) {
            case FlowEvent::NEW:
                network_.on_flow_new(f);
                break;

            case FlowEvent::UPDATED: {
                // Compute delta bytes since last update
                // Store prev_bytes in flow or compute from counters
                uint64_t in  = f.fwd_bytes;
                uint64_t out = f.rev_bytes;
                network_.on_flow_updated(f, in, out);
                // DNS transaction matching
                if (f.app_protocol == AppProtocol::DNS && !f.dns_query.empty())
                    ; // DNS latency matched in separate DnsTracker (see below)
                break;
            }

            case FlowEvent::CLOSED:
            case FlowEvent::EXPIRED:
                network_.on_flow_closed(f);
                tcp_.on_flow_closed(f);
                break;
        }
    }

    // Called by DnsTracker when request+response are matched
    void on_dns_resolved(const std::string& domain, uint32_t latency_ms,
                         bool nxdomain, int64_t ts) {
        dns_.on_dns_resolved(domain, latency_ms, nxdomain, ts);
    }

    // Called when HTTP request+response are matched within a flow
    void on_http_transaction(const std::string& method, const std::string& url,
                             const std::string& host, int status,
                             uint32_t latency_ms, uint64_t resp_bytes, int64_t ts) {
        http_.on_http_transaction(method, url, host, status, latency_ms, resp_bytes, ts);
    }

    // ── AI context snapshot ────────────────────────────────────────────────
    // This is what gets sent to the LLM — compact, no raw packets
    nlohmann::json ai_context_snapshot(size_t window_sec = 60) const {
        auto net = network_.snapshot(window_sec);
        auto tcp = tcp_.snapshot(window_sec);
        auto dns = dns_.snapshot(window_sec);
        auto http= http_.snapshot(window_sec);

        nlohmann::json j;
        j["window_sec"]          = window_sec;

        j["network"]["bps_in"]   = net.bytes_in_per_sec * 8;
        j["network"]["bps_out"]  = net.bytes_out_per_sec * 8;
        j["network"]["pps"]      = net.packets_per_sec;
        j["network"]["active_flows"] = net.active_flows;
        j["network"]["new_flows_per_sec"] = net.new_flows_per_sec;

        // Top talkers — just top 5 for LLM context (keep prompt small)
        auto& tt = j["network"]["top_talkers"];
        for (size_t i = 0; i < std::min(net.top_talkers.size(), size_t(5)); ++i)
            tt.push_back({{"ip", net.top_talkers[i].key},
                          {"bytes", net.top_talkers[i].value}});

        j["tcp"]["rtt_p50_us"]   = tcp.rtt_p50_us;
        j["tcp"]["rtt_p95_us"]   = tcp.rtt_p95_us;
        j["tcp"]["rtt_p99_us"]   = tcp.rtt_p99_us;
        j["tcp"]["retransmit_pct"] = tcp.retransmission_rate_pct;
        j["tcp"]["zero_window_rate"] = tcp.zero_window_rate;
        j["tcp"]["avg_flow_duration_ms"] = tcp.avg_flow_duration_ms;

        j["dns"]["avg_resolution_ms"] = dns.avg_resolution_ms;
        j["dns"]["p95_resolution_ms"] = dns.p95_resolution_ms;
        j["dns"]["nxdomain_pct"]      = dns.nxdomain_rate_pct;
        j["dns"]["queries_per_sec"]   = dns.queries_per_sec;

        // Slowest DNS domains — top 3 for LLM
        auto& sd = j["dns"]["slowest_domains"];
        for (size_t i = 0; i < std::min(dns.slowest_domains.size(), size_t(3)); ++i)
            sd.push_back({{"domain", dns.slowest_domains[i].key},
                          {"avg_ms", dns.slowest_domains[i].avg}});

        j["http"]["req_per_sec"]   = http.req_per_sec;
        j["http"]["p50_ms"]        = http.latency_p50_ms;
        j["http"]["p95_ms"]        = http.latency_p95_ms;
        j["http"]["p99_ms"]        = http.latency_p99_ms;
        j["http"]["error_rate_pct"] = http.error_rate_pct;

        // Slowest endpoints — top 3 for LLM
        auto& se = j["http"]["slowest_endpoints"];
        for (size_t i = 0; i < std::min(http.slowest_endpoints.size(), size_t(3)); ++i)
            se.push_back({{"endpoint", http.slowest_endpoints[i].key},
                          {"avg_ms",   http.slowest_endpoints[i].avg}});

        return j;
    }

    void start_housekeeping() {
        running_ = true;
        housekeeping_thread_ = std::thread([this]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                // Reset histograms so stale percentiles don't carry forward
                tcp_.reset_histogram();
                dns_.reset_histogram();
                http_.reset_histogram();
                // Reset top-N trackers so bursts don't dominate forever
                // (keep them rolling rather than cumulative)
            }
        });
    }

    void stop_housekeeping() {
        running_ = false;
        if (housekeeping_thread_.joinable()) housekeeping_thread_.join();
    }

private:
    NetworkMetrics network_;
    TcpMetrics     tcp_;
    DnsMetrics     dns_;
    HttpMetrics    http_;
    std::atomic<bool> running_{false};
    std::thread housekeeping_thread_;
};
```

---

## The DNS transaction matcher — the hardest part of DnsMetrics

DNS latency isn't in the packet. It's the delta between when you saw a DNS query and when you saw its response. They arrive on different packets, potentially seconds apart. You need a transaction tracker:

```cpp
#pragma once
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <functional>

// Matches DNS queries to their responses by transaction_id within a flow
class DnsTransactionTracker {
public:
    using ResolvedCallback = std::function<void(
        const std::string& domain, uint32_t latency_ms, bool nxdomain, int64_t ts)>;

    explicit DnsTransactionTracker(ResolvedCallback cb) : callback_(std::move(cb)) {}

    void on_dns_packet(uint64_t flow_id, const DnsFields& dns, int64_t ts_ns) {
        std::lock_guard lock(mtx_);

        if (!dns.is_response) {
            // Store query — key = flow_id + transaction_id
            uint64_t key = (flow_id << 16) ^ dns.transaction_id;
            pending_[key] = { dns.query_name, ts_ns };
            // Evict if too old (> 5 seconds)
            evict_stale(ts_ns);
        } else {
            // Match to pending query
            uint64_t key = (flow_id << 16) ^ dns.transaction_id;
            auto it = pending_.find(key);
            if (it != pending_.end()) {
                uint32_t latency_ms = static_cast<uint32_t>(
                    (ts_ns - it->second.query_ts_ns) / 1'000'000LL);
                bool nxdomain = (dns.rcode == 3);
                callback_(it->second.query_name, latency_ms, nxdomain,
                          ts_ns / 1'000'000'000LL);
                pending_.erase(it);
            }
        }
    }

private:
    struct PendingQuery { std::string name; int64_t query_ts_ns; };
    mutable std::mutex mtx_;
    std::unordered_map<uint64_t, PendingQuery> pending_;
    ResolvedCallback callback_;

    void evict_stale(int64_t now_ns) {
        int64_t cutoff = now_ns - 5'000'000'000LL; // 5 seconds
        for (auto it = pending_.begin(); it != pending_.end(); ) {
            if (it->second.query_ts_ns < cutoff) it = pending_.erase(it);
            else ++it;
        }
    }
};
```

---

## REST API endpoints

```cpp
// In your Drogon API setup:

// GET /api/metrics/network?window=60
app.registerHandler("/api/metrics/network",
    [&metrics_engine](const HttpRequest& req, ResponseWriter writer) {
        int window = std::stoi(req.getParameter("window").value_or("60"));
        auto snap = metrics_engine.network_.snapshot(window);
        // serialize to JSON...
        writer(HttpResponse::newHttpJsonResponse(to_json(snap)));
    });

// GET /api/metrics/ai-context
// This is what the AI copilot calls before answering a user question
app.registerHandler("/api/metrics/ai-context",
    [&metrics_engine](const HttpRequest& req, ResponseWriter writer) {
        int window = std::stoi(req.getParameter("window").value_or("60"));
        auto ctx = metrics_engine.ai_context_snapshot(window);
        writer(HttpResponse::newHttpJsonResponse(ctx));
    });

// GET /api/metrics/summary
// Dashboard overview page — all four sub-engines in one call
app.registerHandler("/api/metrics/summary",
    [&metrics_engine](const HttpRequest& req, ResponseWriter writer) {
        int w = std::stoi(req.getParameter("window").value_or("60"));
        nlohmann::json j;
        j["network"] = to_json(metrics_engine.network_.snapshot(w));
        j["tcp"]     = to_json(metrics_engine.tcp_.snapshot(w));
        j["dns"]     = to_json(metrics_engine.dns_.snapshot(w));
        j["http"]    = to_json(metrics_engine.http_.snapshot(w));
        writer(HttpResponse::newHttpJsonResponse(j));
    });
```

---

## Project structure additions

```
core/
└── metrics/
    ├── metric_window.hpp          ← ring buffer template
    ├── latency_histogram.hpp      ← fixed-bucket percentile tracker
    ├── topn_tracker.hpp           ← top-N by count or latency
    ├── dns_transaction_tracker.hpp← query/response matcher
    ├── network_metrics.hpp        ← bps/pps/top-talkers
    ├── tcp_metrics.hpp            ← RTT/rexmit/zero-window
    ├── dns_metrics.hpp            ← resolution latency/domains
    ├── http_metrics.hpp           ← p50/p95/p99/error-rate
    ├── metrics_engine.hpp         ← aggregator + AI snapshot
    └── metrics_engine.cpp
```

---

## Implementation order

1. `MetricBucket` + `MetricWindow<N>` — write unit tests: record 10 values, verify `summarize()` returns correct avg and rate
2. `LatencyHistogram` — record 1000 random latencies, verify p50/p95/p99 are sensible
3. `TopNTracker` — insert 10k entries, verify `top_by_count(10)` returns correct top 10
4. `NetworkMetrics` — wire to FlowEngine, print `snapshot()` to stdout every 5 seconds, verify bps tracks a file download
5. `TcpMetrics` — run a `wget` session, verify RTT p50 is close to `ping` RTT
6. `DnsTransactionTracker` — run `dig google.com` 10 times, verify latency matches
7. `DnsMetrics` — verify top domains shows google.com at the top
8. `HttpMetrics` — run `curl http://example.com` in a loop, verify p95 latency and req/sec
9. `ai_context_snapshot()` — print the JSON, verify it's compact and accurate
10. REST endpoints — call `/api/metrics/summary` from browser, verify live data

The key insight for ordering: each step produces visible console output you can manually verify. Never move to the next step until the current one's output matches what you'd expect from a packet capture.

---

Module 4 is the engine that makes your AI Copilot work. When a user asks "why is my API slow?" the AI layer calls `/api/metrics/ai-context`, gets back a compact JSON with `http.p95_ms = 3200`, `dns.avg_resolution_ms = 410`, `tcp.retransmit_pct = 8.3`, and produces a specific, accurate root cause analysis instead of a generic answer. That's the whole point of building all of this first.

Ready to go into Module 5 (Detection Engine) next?