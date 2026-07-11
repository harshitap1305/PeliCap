Module 5 
Let me dive straight into the full implementation plan for Module 5.

---

## Module 5 — Detection Engine: Complete Implementation Plan

---

## What this module does and why it's different from Module 4

Module 4 measures. Module 5 judges. The metrics engine computes `retransmission_rate = 8.3%`. The detection engine looks at that number and decides: that's abnormal, fire an alert. The distinction matters because detection requires:

- **Baselines** — you can't call 8.3% "high" without knowing what normal looks like for this network
- **Thresholds** — configurable per-deployment, not hardcoded
- **Cooldowns** — an alert that fires every second for the same condition is noise, not signal
- **Severity levels** — a retransmission spike is WARNING, a port scan is CRITICAL
- **Context enrichment** — an alert should say "retransmission rate spiked to 8.3% on flows to 34.120.50.1, affecting 12 connections" not just "retransmission rate high"

Every detector follows the same lifecycle: observe → compare against baseline or threshold → decide → emit alert with cooldown. Build that lifecycle once as a base class, then write each detector as a small focused subclass.

---

## The Alert struct — design it first, everything else follows

```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <nlohmann/json.hpp>

enum class AlertSeverity : uint8_t {
    INFO     = 0,   // informational — worth logging, no action needed
    WARNING  = 1,   // degraded performance — investigate
    CRITICAL = 2,   // service impact — act now
};

enum class AlertType : uint16_t {
    // TCP quality
    TCP_RETRANSMISSION_SPIKE  = 100,
    TCP_ZERO_WINDOW           = 101,
    TCP_HIGH_RTT              = 102,
    TCP_SYN_FLOOD             = 103,
    TCP_RST_FLOOD             = 104,
    TCP_LONG_LIVED_CONNECTION = 105,

    // DNS
    DNS_HIGH_LATENCY          = 200,
    DNS_NXDOMAIN_SPIKE        = 201,
    DNS_QUERY_FLOOD           = 202,
    DNS_SINGLE_DOMAIN_FLOOD   = 203,

    // HTTP
    HTTP_ERROR_RATE_SPIKE     = 300,
    HTTP_LATENCY_SPIKE        = 301,
    HTTP_REQUEST_FLOOD        = 302,

    // Network / traffic
    TRAFFIC_SPIKE             = 400,
    TRAFFIC_DROP              = 401,
    PORT_SCAN                 = 500,
    HOST_SCAN                 = 501,
    LARGE_FLOW                = 600,
};

struct AlertContext {
    // Populated per-alert type — not all fields used by every alert
    std::string  src_ip;
    std::string  dst_ip;
    uint16_t     src_port    = 0;
    uint16_t     dst_port    = 0;
    std::string  domain;           // for DNS alerts
    std::string  endpoint;         // for HTTP alerts
    double       observed_value  = 0.0;
    double       threshold_value = 0.0;
    double       baseline_value  = 0.0;
    uint64_t     flow_id         = 0;
    uint32_t     affected_flows  = 0;
    std::string  protocol;
    std::string  extra;            // freeform detail string
};

struct Alert {
    uint64_t      alert_id    = 0;        // monotonically increasing
    AlertType     type;
    AlertSeverity severity;
    int64_t       timestamp_ns = 0;
    std::string   title;                  // one-line human summary
    std::string   description;            // 2-3 sentence explanation
    AlertContext  context;
    bool          is_ongoing  = false;    // true = condition still active
    int64_t       resolved_at_ns = 0;     // 0 = not yet resolved

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["alert_id"]    = alert_id;
        j["type"]        = static_cast<int>(type);
        j["severity"]    = static_cast<int>(severity);
        j["timestamp_ns"]= timestamp_ns;
        j["title"]       = title;
        j["description"] = description;
        j["is_ongoing"]  = is_ongoing;
        if (!context.src_ip.empty())   j["src_ip"]   = context.src_ip;
        if (!context.dst_ip.empty())   j["dst_ip"]   = context.dst_ip;
        if (!context.domain.empty())   j["domain"]   = context.domain;
        if (!context.endpoint.empty()) j["endpoint"] = context.endpoint;
        j["observed"]    = context.observed_value;
        j["threshold"]   = context.threshold_value;
        return j;
    }
};
```

---

## The Baseline system — the most important production detail

Every threshold-based detector needs a baseline. Without one, you hardcode `retransmit > 5%` as the threshold and it fires constantly on a congested network where 5% is normal, or never fires on a clean network where 2% is already suspicious.

The right approach is an **exponentially weighted moving average (EWMA)** baseline. Simple to implement, adapts automatically to the network's normal behavior, and uses almost no memory.

```cpp
#pragma once
#include <cstdint>
#include <cmath>
#include <mutex>

// EWMA baseline tracker
// Smoothing factor alpha: 0.1 = slow adaptation (stable), 0.3 = fast adaptation
// Formula: baseline = alpha * new_value + (1 - alpha) * old_baseline
class EwmaBaseline {
public:
    explicit EwmaBaseline(double alpha = 0.1, double initial = -1.0)
        : alpha_(alpha), value_(initial), initialized_(initial >= 0) {}

    void update(double new_value) {
        std::lock_guard lock(mtx_);
        if (!initialized_) {
            value_       = new_value;
            initialized_ = true;
            return;
        }
        value_ = alpha_ * new_value + (1.0 - alpha_) * value_;

        // Track variance for dynamic thresholding (Welford's online algorithm)
        double delta  = new_value - value_;
        double delta2 = new_value - value_;
        mean_     += delta  / ++count_;
        variance_ += delta * delta2;
    }

    double get()    const { std::lock_guard lock(mtx_); return value_; }
    bool   ready()  const { std::lock_guard lock(mtx_); return initialized_ && count_ >= 10; }

    // Dynamic threshold: baseline + N standard deviations
    // e.g. threshold = baseline + 3 * stddev means "3 sigma above normal"
    double dynamic_threshold(double sigma_multiplier = 3.0) const {
        std::lock_guard lock(mtx_);
        if (count_ < 2) return value_ * 2.0; // fallback before enough data
        double stddev = std::sqrt(variance_ / count_);
        return value_ + sigma_multiplier * stddev;
    }

private:
    mutable std::mutex mtx_;
    double   alpha_;
    double   value_;
    bool     initialized_;
    uint64_t count_    = 0;
    double   mean_     = 0.0;
    double   variance_ = 0.0;
};
```

Each detector maintains its own `EwmaBaseline` instance. The baseline is updated every minute with the observed metric value. After 10 minutes it's considered "warmed up" and dynamic thresholding kicks in.

---

## The Cooldown system — prevents alert storms

```cpp
#pragma once
#include <unordered_map>
#include <string>
#include <chrono>
#include <mutex>

// Tracks last fire time per alert key
// Key format: "AlertType:context_key" e.g. "TCP_HIGH_RTT:192.168.1.10"
class CooldownTracker {
public:
    explicit CooldownTracker(int64_t default_cooldown_ns = 60'000'000'000LL)
        : default_cooldown_ns_(default_cooldown_ns) {}

    // Returns true if the alert is allowed to fire (cooldown has expired)
    bool can_fire(const std::string& key, int64_t now_ns,
                  int64_t cooldown_override_ns = -1)
    {
        std::lock_guard lock(mtx_);
        int64_t cooldown = cooldown_override_ns >= 0
                           ? cooldown_override_ns
                           : default_cooldown_ns_;
        auto it = last_fire_.find(key);
        if (it == last_fire_.end() || (now_ns - it->second) >= cooldown) {
            last_fire_[key] = now_ns;
            return true;
        }
        return false;
    }

    // Mark an alert as resolved — resets cooldown for that key
    void reset(const std::string& key) {
        std::lock_guard lock(mtx_);
        last_fire_.erase(key);
    }

    // Evict keys older than max_age_ns to prevent unbounded growth
    void evict_old(int64_t now_ns, int64_t max_age_ns = 600'000'000'000LL) {
        std::lock_guard lock(mtx_);
        for (auto it = last_fire_.begin(); it != last_fire_.end(); ) {
            if (now_ns - it->second > max_age_ns) it = last_fire_.erase(it);
            else ++it;
        }
    }

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, int64_t> last_fire_;
    int64_t default_cooldown_ns_;
};
```

---

## The DetectorBase — one base class, all detectors inherit it

```cpp
#pragma once
#include "alert.hpp"
#include "cooldown_tracker.hpp"
#include "ewma_baseline.hpp"
#include <functional>
#include <atomic>

using AlertCallback = std::function<void(Alert)>;

class DetectorBase {
public:
    struct Config {
        bool    enabled             = true;
        double  threshold           = 0.0;     // static threshold (used before baseline ready)
        double  sigma_multiplier    = 3.0;     // dynamic threshold = baseline + N * sigma
        int64_t cooldown_ns         = 60'000'000'000LL;  // 60 seconds default
        bool    use_dynamic_threshold = true;
    };

    explicit DetectorBase(Config cfg, AlertCallback cb)
        : config_(cfg), callback_(std::move(cb)),
          cooldown_(cfg.cooldown_ns) {}

    virtual ~DetectorBase() = default;

    bool is_enabled() const { return config_.enabled; }
    void set_enabled(bool v) { config_.enabled = v; }
    void set_threshold(double t) { config_.threshold = t; }

protected:
    // Subclasses call this to fire an alert with cooldown enforcement
    void fire(Alert alert, const std::string& cooldown_key) {
        if (!config_.enabled) return;
        int64_t now = now_ns();
        if (!cooldown_.can_fire(cooldown_key, now, config_.cooldown_ns)) return;

        alert.alert_id    = next_id_.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp_ns = now;
        alert.is_ongoing  = true;

        if (callback_) callback_(std::move(alert));
    }

    // Returns the effective threshold — dynamic if baseline is ready
    double effective_threshold() const {
        if (config_.use_dynamic_threshold && baseline_.ready())
            return baseline_.dynamic_threshold(config_.sigma_multiplier);
        return config_.threshold;
    }

    void update_baseline(double value) { baseline_.update(value); }

    static int64_t now_ns() {
        return std::chrono::steady_clock::now().time_since_epoch().count();
    }

    Config           config_;
    AlertCallback    callback_;
    CooldownTracker  cooldown_;
    EwmaBaseline     baseline_;

private:
    static std::atomic<uint64_t> next_id_;
};

std::atomic<uint64_t> DetectorBase::next_id_{1};
```

---

## The individual detectors

### 1. TcpRetransmissionDetector

```cpp
#pragma once
#include "detector_base.hpp"
#include "../metrics/tcp_metrics.hpp"

class TcpRetransmissionDetector : public DetectorBase {
public:
    explicit TcpRetransmissionDetector(AlertCallback cb)
        : DetectorBase({
            .enabled           = true,
            .threshold         = 5.0,    // 5% static fallback
            .sigma_multiplier  = 3.0,
            .cooldown_ns       = 60'000'000'000LL,  // 1 minute
            .use_dynamic_threshold = true
          }, std::move(cb)) {}

    // Called every 10 seconds by the DetectionEngine tick
    void evaluate(const TcpMetrics::Snapshot& snap) {
        double rate = snap.retransmission_rate_pct;
        update_baseline(rate);

        double threshold = effective_threshold();
        if (rate <= threshold) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = threshold;
        ctx.baseline_value  = baseline_.get();
        ctx.affected_flows  = snap.worst_rtt_flows.size();

        // Add worst RTT flow info for context
        if (!snap.worst_rtt_flows.empty()) {
            ctx.extra = "worst flow: " + snap.worst_rtt_flows[0].key +
                        " avg_rtt=" + std::to_string(snap.worst_rtt_flows[0].avg) + "ms";
        }

        AlertSeverity sev = rate > threshold * 2.0
                            ? AlertSeverity::CRITICAL
                            : AlertSeverity::WARNING;

        Alert a;
        a.type       = AlertType::TCP_RETRANSMISSION_SPIKE;
        a.severity   = sev;
        a.title      = "TCP retransmission rate elevated: "
                      + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "Retransmission rate of " + std::to_string(rate)
                      + "% exceeds baseline of "
                      + std::to_string(baseline_.get()) + "%. "
                      + "This indicates packet loss or network congestion. "
                      + ctx.extra;
        a.context    = ctx;

        fire(std::move(a), "tcp_retransmit");
    }
};
```

### 2. HighRttDetector

```cpp
class HighRttDetector : public DetectorBase {
public:
    explicit HighRttDetector(AlertCallback cb)
        : DetectorBase({
            .enabled           = true,
            .threshold         = 200'000,  // 200ms in microseconds
            .sigma_multiplier  = 3.0,
            .cooldown_ns       = 120'000'000'000LL,  // 2 minutes
          }, std::move(cb)) {}

    void evaluate(const TcpMetrics::Snapshot& snap) {
        double p95 = snap.rtt_p95_us;
        update_baseline(p95);

        double threshold = effective_threshold();
        if (p95 <= threshold) return;

        Alert a;
        a.type        = AlertType::TCP_HIGH_RTT;
        a.severity    = p95 > 500'000 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title       = "High TCP RTT: p95=" + std::to_string(p95 / 1000) + "ms";
        a.description = "95th percentile RTT is " + std::to_string(p95 / 1000)
                      + "ms, above baseline of "
                      + std::to_string(static_cast<int>(baseline_.get() / 1000))
                      + "ms. Users may experience slow response times.";
        a.context.observed_value  = p95;
        a.context.threshold_value = threshold;

        fire(std::move(a), "tcp_high_rtt");
    }
};
```

### 3. DnsLatencyDetector

```cpp
class DnsLatencyDetector : public DetectorBase {
public:
    explicit DnsLatencyDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 200.0,    // 200ms static fallback
            .sigma_multiplier = 3.0,
            .cooldown_ns      = 120'000'000'000LL,
          }, std::move(cb)) {}

    void evaluate(const DnsMetrics::Snapshot& snap) {
        double p95 = snap.p95_resolution_ms;
        update_baseline(snap.avg_resolution_ms);

        double threshold = effective_threshold();
        if (p95 <= threshold) return;

        AlertContext ctx;
        ctx.observed_value  = p95;
        ctx.threshold_value = threshold;
        ctx.baseline_value  = baseline_.get();

        // Identify which domains are slow
        if (!snap.slowest_domains.empty()) {
            ctx.domain = snap.slowest_domains[0].key;
            ctx.extra  = "slowest: " + ctx.domain
                       + " avg=" + std::to_string(static_cast<int>(snap.slowest_domains[0].avg)) + "ms";
        }

        Alert a;
        a.type        = AlertType::DNS_HIGH_LATENCY;
        a.severity    = p95 > 1000.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title       = "DNS resolution slow: p95=" + std::to_string(static_cast<int>(p95)) + "ms";
        a.description = "DNS p95 latency is " + std::to_string(static_cast<int>(p95))
                      + "ms, above baseline of "
                      + std::to_string(static_cast<int>(baseline_.get()))
                      + "ms. " + ctx.extra
                      + ". This contributes directly to API response time.";
        a.context = ctx;

        fire(std::move(a), "dns_latency");
    }
};
```

### 4. DnsNxdomainDetector

```cpp
class DnsNxdomainDetector : public DetectorBase {
public:
    explicit DnsNxdomainDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 10.0,   // 10% NXDOMAIN rate static fallback
            .sigma_multiplier = 4.0,    // higher sigma — NXDOMAIN bursts are uncommon
            .cooldown_ns      = 300'000'000'000LL,  // 5 minutes
          }, std::move(cb)) {}

    void evaluate(const DnsMetrics::Snapshot& snap) {
        double rate = snap.nxdomain_rate_pct;
        update_baseline(rate);

        double threshold = effective_threshold();
        if (rate <= threshold) return;

        Alert a;
        a.type        = AlertType::DNS_NXDOMAIN_SPIKE;
        a.severity    = rate > 40.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title       = "High DNS NXDOMAIN rate: " + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "NXDOMAIN rate of " + std::to_string(rate)
                      + "% suggests misconfigured clients, DNS-based malware C2 beaconing, "
                      + "or a deployment pushing queries to a wrong domain.";
        a.context.observed_value  = rate;
        a.context.threshold_value = threshold;

        fire(std::move(a), "dns_nxdomain");
    }
};
```

### 5. HttpErrorRateDetector

```cpp
class HttpErrorRateDetector : public DetectorBase {
public:
    explicit HttpErrorRateDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 5.0,    // 5% error rate
            .sigma_multiplier = 3.0,
            .cooldown_ns      = 60'000'000'000LL,
          }, std::move(cb)) {}

    void evaluate(const HttpMetrics::Snapshot& snap) {
        double rate = snap.error_rate_pct;
        update_baseline(rate);

        double threshold = effective_threshold();
        if (rate <= threshold) return;

        AlertContext ctx;
        ctx.observed_value  = rate;
        ctx.threshold_value = threshold;
        if (!snap.slowest_endpoints.empty())
            ctx.endpoint = snap.slowest_endpoints[0].key;

        Alert a;
        a.type      = AlertType::HTTP_ERROR_RATE_SPIKE;
        a.severity  = rate > 25.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title     = "HTTP error rate elevated: " + std::to_string(static_cast<int>(rate)) + "%";
        a.description = "HTTP 4xx/5xx error rate is " + std::to_string(rate)
                      + "%, above baseline of "
                      + std::to_string(static_cast<int>(baseline_.get()))
                      + "%. Check application logs for root cause.";
        a.context = ctx;

        fire(std::move(a), "http_error_rate");
    }
};
```

### 6. HttpLatencyDetector

```cpp
class HttpLatencyDetector : public DetectorBase {
public:
    explicit HttpLatencyDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 1000.0,   // 1 second p95
            .sigma_multiplier = 3.0,
            .cooldown_ns      = 120'000'000'000LL,
          }, std::move(cb)) {}

    void evaluate(const HttpMetrics::Snapshot& snap) {
        double p95 = snap.latency_p95_ms;
        update_baseline(snap.latency_p50_ms);   // baseline tracks p50 (normal)

        double threshold = effective_threshold();
        if (p95 <= threshold) return;

        AlertContext ctx;
        ctx.observed_value  = p95;
        ctx.threshold_value = threshold;
        if (!snap.slowest_endpoints.empty()) {
            ctx.endpoint = snap.slowest_endpoints[0].key;
            ctx.extra    = "slowest endpoint: " + ctx.endpoint
                         + " avg=" + std::to_string(static_cast<int>(snap.slowest_endpoints[0].avg)) + "ms";
        }

        Alert a;
        a.type        = AlertType::HTTP_LATENCY_SPIKE;
        a.severity    = p95 > 5000.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title       = "HTTP latency spike: p95=" + std::to_string(static_cast<int>(p95)) + "ms";
        a.description = "HTTP p95 response time is " + std::to_string(static_cast<int>(p95))
                      + "ms. " + ctx.extra;
        a.context = ctx;

        fire(std::move(a), "http_latency");
    }
};
```

### 7. TrafficSpikeDetector

```cpp
class TrafficSpikeDetector : public DetectorBase {
public:
    explicit TrafficSpikeDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 100'000'000.0,  // 100 MB/s static fallback
            .sigma_multiplier = 4.0,            // needs higher sigma — traffic is noisy
            .cooldown_ns      = 30'000'000'000LL,  // 30 seconds
          }, std::move(cb)) {}

    void evaluate(const NetworkMetrics::Snapshot& snap) {
        double total_bps = (snap.bytes_in_per_sec + snap.bytes_out_per_sec) * 8;
        update_baseline(total_bps);

        // Also check for traffic DROP (sudden silence is also suspicious)
        if (baseline_.ready()) {
            double floor = baseline_.get() * 0.1;  // 10% of baseline = suspicious drop
            if (total_bps < floor && baseline_.get() > 1'000'000) {
                Alert a;
                a.type        = AlertType::TRAFFIC_DROP;
                a.severity    = AlertSeverity::WARNING;
                a.title       = "Traffic drop: " + format_bps(total_bps) + " (was " + format_bps(baseline_.get()) + ")";
                a.description = "Traffic dropped to " + format_bps(total_bps)
                              + ", which is less than 10% of the recent baseline of "
                              + format_bps(baseline_.get())
                              + ". Possible network outage or interface issue.";
                a.context.observed_value  = total_bps;
                a.context.threshold_value = floor;
                fire(std::move(a), "traffic_drop");
            }
        }

        double threshold = effective_threshold();
        if (total_bps <= threshold) return;

        AlertContext ctx;
        ctx.observed_value  = total_bps;
        ctx.threshold_value = threshold;
        ctx.baseline_value  = baseline_.get();

        if (!snap.top_talkers.empty())
            ctx.src_ip = snap.top_talkers[0].key;

        Alert a;
        a.type        = AlertType::TRAFFIC_SPIKE;
        a.severity    = total_bps > threshold * 3.0 ? AlertSeverity::CRITICAL : AlertSeverity::WARNING;
        a.title       = "Traffic spike: " + format_bps(total_bps);
        a.description = "Traffic spiked to " + format_bps(total_bps)
                      + ", above baseline of " + format_bps(baseline_.get())
                      + ". Top source: " + ctx.src_ip;
        a.context = ctx;

        fire(std::move(a), "traffic_spike");
    }

private:
    static std::string format_bps(double bps) {
        if (bps > 1e9) return std::to_string(static_cast<int>(bps / 1e9)) + " Gbps";
        if (bps > 1e6) return std::to_string(static_cast<int>(bps / 1e6)) + " Mbps";
        return std::to_string(static_cast<int>(bps / 1e3)) + " Kbps";
    }
};
```

### 8. PortScanDetector — stateful, not threshold-based

This one is fundamentally different from the others. A port scan isn't a spike in a metric — it's a behavioral pattern: one source IP touching many different destination ports in a short window. You need a per-source-IP counter that resets every minute.

```cpp
#pragma once
#include "detector_base.hpp"
#include <unordered_map>
#include <unordered_set>
#include <mutex>

class PortScanDetector : public DetectorBase {
public:
    struct ScanConfig {
        uint32_t ports_per_minute_threshold = 20;   // 20 distinct ports in 60s = suspicious
        uint32_t hosts_per_minute_threshold = 15;   // 15 distinct hosts in 60s = host scan
        int64_t  window_ns = 60'000'000'000LL;      // 60 second observation window
    };

    explicit PortScanDetector(AlertCallback cb, ScanConfig scan_cfg = {})
        : DetectorBase({
            .enabled     = true,
            .cooldown_ns = 300'000'000'000LL,  // 5 minutes
          }, std::move(cb)),
          scan_config_(scan_cfg) {}

    // Called for EVERY new flow (from FlowEngine FLOW_NEW event)
    void on_new_flow(const std::string& src_ip, const std::string& dst_ip,
                     uint16_t dst_port, int64_t ts_ns)
    {
        std::lock_guard lock(mtx_);
        evict_stale(ts_ns);

        // Track distinct ports per source IP
        auto& entry = per_src_[src_ip];
        entry.dst_ports.insert(dst_port);
        entry.dst_hosts.insert(dst_ip);
        entry.first_seen_ns = std::min(entry.first_seen_ns, ts_ns);
        entry.last_seen_ns  = ts_ns;

        // Check for port scan
        if (entry.dst_ports.size() >= scan_config_.ports_per_minute_threshold) {
            AlertContext ctx;
            ctx.src_ip         = src_ip;
            ctx.observed_value = entry.dst_ports.size();
            ctx.threshold_value = scan_config_.ports_per_minute_threshold;
            ctx.extra = "ports scanned: " + std::to_string(entry.dst_ports.size())
                      + " unique destinations: " + std::to_string(entry.dst_hosts.size());

            Alert a;
            a.type        = AlertType::PORT_SCAN;
            a.severity    = AlertSeverity::CRITICAL;
            a.title       = "Port scan detected from " + src_ip;
            a.description = src_ip + " contacted " + std::to_string(entry.dst_ports.size())
                          + " distinct ports in under 60 seconds. "
                          + "This pattern is consistent with automated port scanning. "
                          + ctx.extra;
            a.context = ctx;

            fire(std::move(a), "port_scan:" + src_ip);

            // Reset counter so we don't re-fire immediately
            entry.dst_ports.clear();
        }

        // Check for host scan (many hosts on same port — horizontal scan)
        if (entry.dst_hosts.size() >= scan_config_.hosts_per_minute_threshold) {
            AlertContext ctx;
            ctx.src_ip          = src_ip;
            ctx.observed_value  = entry.dst_hosts.size();
            ctx.threshold_value = scan_config_.hosts_per_minute_threshold;

            Alert a;
            a.type        = AlertType::HOST_SCAN;
            a.severity    = AlertSeverity::CRITICAL;
            a.title       = "Host scan detected from " + src_ip;
            a.description = src_ip + " contacted " + std::to_string(entry.dst_hosts.size())
                          + " distinct hosts in under 60 seconds. "
                          + "This is consistent with network enumeration activity.";
            a.context = ctx;

            fire(std::move(a), "host_scan:" + src_ip);
            entry.dst_hosts.clear();
        }
    }

private:
    struct SrcEntry {
        std::unordered_set<uint16_t>    dst_ports;
        std::unordered_set<std::string> dst_hosts;
        int64_t first_seen_ns = std::numeric_limits<int64_t>::max();
        int64_t last_seen_ns  = 0;
    };

    mutable std::mutex mtx_;
    std::unordered_map<std::string, SrcEntry> per_src_;
    ScanConfig scan_config_;

    void evict_stale(int64_t now_ns) {
        // Remove entries older than the observation window
        for (auto it = per_src_.begin(); it != per_src_.end(); ) {
            if (now_ns - it->second.last_seen_ns > scan_config_.window_ns)
                it = per_src_.erase(it);
            else ++it;
        }
    }
};
```

### 9. LargeFlowDetector

```cpp
class LargeFlowDetector : public DetectorBase {
public:
    struct LargeFlowConfig {
        uint64_t bytes_threshold = 100'000'000ULL;  // 100 MB per flow
        int64_t  duration_threshold_ns = 300'000'000'000LL;  // 5 min long-lived
    };

    explicit LargeFlowDetector(AlertCallback cb, LargeFlowConfig cfg = {})
        : DetectorBase({
            .enabled     = true,
            .cooldown_ns = 600'000'000'000LL,  // 10 minutes per flow
          }, std::move(cb)),
          lf_config_(cfg) {}

    // Called on FLOW_CLOSED or FLOW_EXPIRED from FlowEngine
    void on_flow_closed(const Flow& f) {
        bool is_large    = f.total_bytes() >= lf_config_.bytes_threshold;
        bool is_longlived = f.duration_ns() >= lf_config_.duration_threshold_ns;

        if (!is_large && !is_longlived) return;

        AlertContext ctx;
        ctx.flow_id       = f.flow_id;
        ctx.src_ip        = f.src_ip_str;
        ctx.dst_ip        = f.dst_ip_str;
        ctx.src_port      = f.src_port;
        ctx.dst_port      = f.dst_port;
        ctx.observed_value = f.total_bytes();

        if (is_large) {
            Alert a;
            a.type       = AlertType::LARGE_FLOW;
            a.severity   = AlertSeverity::INFO;
            a.title      = "Large flow: " + format_bytes(f.total_bytes())
                         + " " + f.src_ip_str + " → " + f.dst_ip_str;
            a.description = "Flow transferred " + format_bytes(f.total_bytes())
                          + " over " + std::to_string(f.duration_ns() / 1'000'000'000LL)
                          + " seconds. Protocol: " + std::to_string(f.protocol)
                          + ". SNI: " + f.tls_sni;
            a.context = ctx;
            fire(std::move(a), "large_flow:" + std::to_string(f.flow_id));
        }

        if (is_longlived) {
            Alert a;
            a.type       = AlertType::TCP_LONG_LIVED_CONNECTION;
            a.severity   = AlertSeverity::INFO;
            a.title      = "Long-lived connection: " + f.src_ip_str + " → " + f.dst_ip_str
                         + " (" + std::to_string(f.duration_ns() / 60'000'000'000LL) + " min)";
            a.description = "Connection open for "
                          + std::to_string(f.duration_ns() / 60'000'000'000LL)
                          + " minutes. May indicate a persistent tunnel, slow leak, or idle keep-alive.";
            a.context = ctx;
            fire(std::move(a), "longlived:" + std::to_string(f.flow_id));
        }
    }

private:
    LargeFlowConfig lf_config_;

    static std::string format_bytes(uint64_t b) {
        if (b > 1'000'000'000ULL) return std::to_string(b / 1'000'000'000ULL) + " GB";
        if (b > 1'000'000ULL)     return std::to_string(b / 1'000'000ULL) + " MB";
        return std::to_string(b / 1000ULL) + " KB";
    }
};
```

### 10. SynFloodDetector

```cpp
class SynFloodDetector : public DetectorBase {
public:
    explicit SynFloodDetector(AlertCallback cb)
        : DetectorBase({
            .enabled          = true,
            .threshold        = 1000.0,   // 1000 SYNs/sec static fallback
            .sigma_multiplier = 5.0,      // very high sigma — SYN floods are distinctive
            .cooldown_ns      = 30'000'000'000LL,
          }, std::move(cb)) {}

    void on_new_tcp_flow_with_syn(const Flow& f, int64_t ts_sec) {
        // Increment per-destination counter
        std::lock_guard lock(mtx_);
        auto& count = syn_per_dst_per_sec_[f.dst_ip_str];
        count.total++;
        count.last_ts = ts_sec;

        // Clean stale entries
        if (ts_sec - last_evict_ > 5) {
            for (auto it = syn_per_dst_per_sec_.begin(); it != syn_per_dst_per_sec_.end(); ) {
                if (ts_sec - it->second.last_ts > 10) it = syn_per_dst_per_sec_.erase(it);
                else ++it;
            }
            last_evict_ = ts_sec;
        }

        // Check threshold
        update_baseline(count.total);
        if (count.total < static_cast<uint64_t>(effective_threshold())) return;

        Alert a;
        a.type       = AlertType::TCP_SYN_FLOOD;
        a.severity   = AlertSeverity::CRITICAL;
        a.title      = "SYN flood towards " + f.dst_ip_str
                     + ": " + std::to_string(count.total) + " SYNs/sec";
        a.description = "Destination " + f.dst_ip_str + " is receiving "
                      + std::to_string(count.total)
                      + " TCP SYN packets per second. "
                      + "This is consistent with a SYN flood denial-of-service attack.";
        a.context.dst_ip          = f.dst_ip_str;
        a.context.observed_value  = count.total;
        a.context.threshold_value = effective_threshold();

        fire(std::move(a), "syn_flood:" + f.dst_ip_str);
        count.total = 0;  // reset after firing
    }

private:
    struct SynCount { uint64_t total = 0; int64_t last_ts = 0; };
    mutable std::mutex mtx_;
    std::unordered_map<std::string, SynCount> syn_per_dst_per_sec_;
    int64_t last_evict_ = 0;
};
```

---

## The AlertStore — in-memory ring buffer with PostgreSQL flush

```cpp
#pragma once
#include "alert.hpp"
#include <deque>
#include <mutex>
#include <vector>
#include <functional>

class AlertStore {
public:
    explicit AlertStore(size_t max_in_memory = 10000) : max_size_(max_in_memory) {}

    void push(Alert alert) {
        std::lock_guard lock(mtx_);
        if (alerts_.size() >= max_size_) alerts_.pop_front();
        alerts_.push_back(std::move(alert));
        if (pg_callback_) pg_callback_(alerts_.back());
    }

    // Get recent alerts — filters by severity and time window
    std::vector<Alert> recent(size_t n = 100,
                              AlertSeverity min_severity = AlertSeverity::INFO) const
    {
        std::lock_guard lock(mtx_);
        std::vector<Alert> result;
        for (auto it = alerts_.rbegin(); it != alerts_.rend() && result.size() < n; ++it) {
            if (it->severity >= min_severity)
                result.push_back(*it);
        }
        return result;
    }

    std::vector<Alert> by_type(AlertType type, size_t n = 50) const {
        std::lock_guard lock(mtx_);
        std::vector<Alert> result;
        for (auto it = alerts_.rbegin(); it != alerts_.rend() && result.size() < n; ++it)
            if (it->type == type) result.push_back(*it);
        return result;
    }

    size_t count() const { std::lock_guard lock(mtx_); return alerts_.size(); }

    // Set callback for PostgreSQL persistence
    void set_persistence_callback(std::function<void(const Alert&)> cb) {
        pg_callback_ = std::move(cb);
    }

private:
    mutable std::mutex mtx_;
    std::deque<Alert>  alerts_;
    size_t             max_size_;
    std::function<void(const Alert&)> pg_callback_;
};
```

---

## The DetectionEngine — wires all detectors together

```cpp
#pragma once
#include "tcp_retransmission_detector.hpp"
#include "high_rtt_detector.hpp"
#include "dns_latency_detector.hpp"
#include "dns_nxdomain_detector.hpp"
#include "http_error_rate_detector.hpp"
#include "http_latency_detector.hpp"
#include "traffic_spike_detector.hpp"
#include "port_scan_detector.hpp"
#include "large_flow_detector.hpp"
#include "syn_flood_detector.hpp"
#include "alert_store.hpp"
#include "../flow/flow_engine.hpp"
#include "../metrics/metrics_engine.hpp"
#include <thread>
#include <atomic>

class DetectionEngine {
public:
    explicit DetectionEngine(AlertStore& store) : store_(store) {
        // Single callback that routes to store and any registered listeners
        auto cb = [this](Alert a) {
            store_.push(a);
            if (external_callback_) external_callback_(std::move(a));
        };

        rexmit_    = std::make_unique<TcpRetransmissionDetector>(cb);
        high_rtt_  = std::make_unique<HighRttDetector>(cb);
        dns_lat_   = std::make_unique<DnsLatencyDetector>(cb);
        dns_nx_    = std::make_unique<DnsNxdomainDetector>(cb);
        http_err_  = std::make_unique<HttpErrorRateDetector>(cb);
        http_lat_  = std::make_unique<HttpLatencyDetector>(cb);
        traffic_   = std::make_unique<TrafficSpikeDetector>(cb);
        port_scan_ = std::make_unique<PortScanDetector>(cb);
        large_flow_= std::make_unique<LargeFlowDetector>(cb);
        syn_flood_ = std::make_unique<SynFloodDetector>(cb);
    }

    // Hook into FlowEngine events
    void on_flow_event(const FlowEventData& ev) {
        const Flow& f = *ev.flow;
        if (ev.event == FlowEvent::NEW) {
            port_scan_->on_new_flow(
                f.src_ip_str, f.dst_ip_str, f.dst_port,
                f.start_time_ns);
            if (f.tcp_state == TcpFlowState::SYN_SENT)
                syn_flood_->on_new_tcp_flow_with_syn(f, f.start_time_ns / 1'000'000'000LL);
        }
        if (ev.event == FlowEvent::CLOSED || ev.event == FlowEvent::EXPIRED)
            large_flow_->on_flow_closed(f);
    }

    // Called every 10 seconds by the tick loop — evaluates metric-based detectors
    void tick(const MetricsEngine& metrics) {
        auto tcp  = metrics.tcp_snapshot(60);
        auto dns  = metrics.dns_snapshot(60);
        auto http = metrics.http_snapshot(60);
        auto net  = metrics.network_snapshot(60);

        rexmit_  ->evaluate(tcp);
        high_rtt_->evaluate(tcp);
        dns_lat_ ->evaluate(dns);
        dns_nx_  ->evaluate(dns);
        http_err_->evaluate(http);
        http_lat_->evaluate(http);
        traffic_ ->evaluate(net);
    }

    void start(MetricsEngine& metrics) {
        running_ = true;
        tick_thread_ = std::thread([this, &metrics]() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                tick(metrics);
            }
        });
    }

    void stop() {
        running_ = false;
        if (tick_thread_.joinable()) tick_thread_.join();
    }

    void set_alert_callback(AlertCallback cb) { external_callback_ = std::move(cb); }

    // Per-detector enable/disable for the REST API
    void set_detector_enabled(AlertType type, bool enabled) {
        switch (type) {
            case AlertType::TCP_RETRANSMISSION_SPIKE: rexmit_->set_enabled(enabled); break;
            case AlertType::TCP_HIGH_RTT:             high_rtt_->set_enabled(enabled); break;
            case AlertType::DNS_HIGH_LATENCY:         dns_lat_->set_enabled(enabled); break;
            case AlertType::HTTP_ERROR_RATE_SPIKE:    http_err_->set_enabled(enabled); break;
            default: break;
        }
    }

private:
    AlertStore& store_;
    AlertCallback external_callback_;
    std::atomic<bool> running_{false};
    std::thread tick_thread_;

    std::unique_ptr<TcpRetransmissionDetector> rexmit_;
    std::unique_ptr<HighRttDetector>           high_rtt_;
    std::unique_ptr<DnsLatencyDetector>        dns_lat_;
    std::unique_ptr<DnsNxdomainDetector>       dns_nx_;
    std::unique_ptr<HttpErrorRateDetector>     http_err_;
    std::unique_ptr<HttpLatencyDetector>       http_lat_;
    std::unique_ptr<TrafficSpikeDetector>      traffic_;
    std::unique_ptr<PortScanDetector>          port_scan_;
    std::unique_ptr<LargeFlowDetector>         large_flow_;
    std::unique_ptr<SynFloodDetector>          syn_flood_;
};
```

---

## REST API endpoints

```
GET  /api/alerts                         — recent alerts (paginated, filter by severity)
GET  /api/alerts?severity=CRITICAL       — only critical alerts
GET  /api/alerts?type=PORT_SCAN          — by type
GET  /api/alerts/:id                     — single alert detail
GET  /api/alerts/count                   — count per severity in last hour
POST /api/detectors/:type/enable         — enable a detector
POST /api/detectors/:type/disable        — disable a detector
POST /api/detectors/:type/threshold      — override static threshold {body: {"threshold": 10.0}}
GET  /api/detectors                      — list all detectors with current config and baseline
```

The `/api/detectors` endpoint is important — it lets your frontend show the current baseline value next to each detector so users understand why an alert fired.

---

## Configuration file — make every threshold tunable

Don't hardcode anything in the detector constructors. Load from a YAML or JSON config at startup:

```json
{
  "detectors": {
    "tcp_retransmission": {
      "enabled": true,
      "static_threshold_pct": 5.0,
      "sigma_multiplier": 3.0,
      "cooldown_sec": 60
    },
    "dns_latency": {
      "enabled": true,
      "static_threshold_ms": 200,
      "sigma_multiplier": 3.0,
      "cooldown_sec": 120
    },
    "port_scan": {
      "enabled": true,
      "ports_per_minute": 20,
      "hosts_per_minute": 15
    },
    "traffic_spike": {
      "enabled": true,
      "sigma_multiplier": 4.0,
      "cooldown_sec": 30
    }
  }
}
```

Load this at startup and pass the values into each detector's `Config`. When the REST API receives a threshold override, write it back to the config and reload.

---

## PostgreSQL schema for alerts

```sql
CREATE TABLE alerts (
    alert_id        BIGINT PRIMARY KEY,
    type            SMALLINT NOT NULL,
    severity        SMALLINT NOT NULL,
    timestamp_ns    BIGINT   NOT NULL,
    title           TEXT     NOT NULL,
    description     TEXT,
    src_ip          INET,
    dst_ip          INET,
    domain          TEXT,
    endpoint        TEXT,
    observed_value  DOUBLE PRECISION,
    threshold_value DOUBLE PRECISION,
    is_ongoing      BOOLEAN  DEFAULT true,
    resolved_at_ns  BIGINT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp_ns DESC);
CREATE INDEX idx_alerts_type      ON alerts(type);
CREATE INDEX idx_alerts_severity  ON alerts(severity);
CREATE INDEX idx_alerts_src_ip    ON alerts(src_ip);
```

---

## Project structure

```
core/
└── detection/
    ├── alert.hpp                        ← Alert struct + AlertType + AlertSeverity
    ├── alert_store.hpp                  ← in-memory deque + pg callback
    ├── cooldown_tracker.hpp             ← per-key cooldown enforcement
    ├── ewma_baseline.hpp                ← EWMA + dynamic threshold
    ├── detector_base.hpp                ← DetectorBase class
    ├── detectors/
    │   ├── tcp_retransmission.hpp
    │   ├── high_rtt.hpp
    │   ├── dns_latency.hpp
    │   ├── dns_nxdomain.hpp
    │   ├── http_error_rate.hpp
    │   ├── http_latency.hpp
    │   ├── traffic_spike.hpp
    │   ├── port_scan.hpp
    │   ├── large_flow.hpp
    │   └── syn_flood.hpp
    ├── detection_engine.hpp
    └── detection_engine.cpp
```

---

## Implementation order

1. `Alert` struct + `AlertStore` — write a test that pushes 20 alerts and reads back the last 5 by severity
2. `CooldownTracker` — verify that calling `can_fire()` twice with the same key within the cooldown returns false the second time
3. `EwmaBaseline` — feed it 50 values, verify `dynamic_threshold()` is sensible and `ready()` returns false before 10 samples
4. `DetectorBase` — write a minimal subclass that always calls `fire()`, verify cooldown works end-to-end
5. `TcpRetransmissionDetector` + `HighRttDetector` — wire to `MetricsEngine`, inject synthetic high retransmission values, verify alerts fire
6. `DnsLatencyDetector` + `DnsNxdomainDetector` — run `dig nonexistent.invalid` in a loop while capturing, verify NXDOMAIN alert fires
7. `HttpErrorRateDetector` + `HttpLatencyDetector` — run a server that returns 500s, verify alert fires
8. `TrafficSpikeDetector` — inject a `iperf3` flood, verify alert fires, verify it stops firing during cooldown
9. `PortScanDetector` — run `nmap -p 1-100 localhost` while capturing, verify port scan alert fires within 5 seconds
10. `SynFloodDetector` + `LargeFlowDetector` — test SYN flood with `hping3`, test large flow with a big file download
11. REST endpoints — verify `/api/alerts` returns correct JSON after triggering alerts manually
12. Config file loading — verify changing threshold via REST API takes effect on next `tick()`

---

## The one thing most people get wrong

They implement static thresholds and call it done. `retransmit > 5%` fires constantly on a congested office network and never fires on a clean production network. The EWMA baseline is what makes the detection engine actually useful — it learns what normal looks like for the specific environment it's deployed in, and detects deviations from that. The first 10 minutes after startup the static threshold applies. After that, the dynamic threshold takes over and adapts automatically. Build the baseline system correctly from the beginning, or your alert center will be full of noise that nobody looks at.

---
