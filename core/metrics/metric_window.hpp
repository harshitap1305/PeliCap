#pragma once
#include <array>
#include <cstdint>
#include <mutex>
#include <vector>
#include <algorithm>
#include <chrono>
#include <limits>

// ── MetricBucket ──────────────────────────────────────────────────────────────
// One time-bucket of accumulated values covering `bucket_width_sec` seconds.

struct MetricBucket {
    int64_t  timestamp_sec = 0;
    uint64_t count         = 0;
    double   sum           = 0.0;
    double   min_val       = std::numeric_limits<double>::max();
    double   max_val       = std::numeric_limits<double>::lowest();
    uint64_t bytes_in      = 0;
    uint64_t bytes_out     = 0;
    uint64_t errors        = 0;

    void reset(int64_t ts) noexcept {
        timestamp_sec = ts;
        count = 0; sum = 0.0; errors = 0; bytes_in = 0; bytes_out = 0;
        min_val = std::numeric_limits<double>::max();
        max_val = std::numeric_limits<double>::lowest();
    }

    void add_sample(double v) noexcept {
        ++count; sum += v;
        min_val = std::min(min_val, v);
        max_val = std::max(max_val, v);
    }

    double avg() const noexcept { return count ? sum / count : 0.0; }
};

// ── MetricWindow<N> ───────────────────────────────────────────────────────────
// Ring buffer of N buckets, each covering `bucket_width_sec` seconds.
//
// IMPORTANT: uses system_clock (wall time) so timestamps align with
// pkt.timestamp_ns from libpcap, which is also wall-clock Unix time.
// Do NOT use steady_clock here — it starts at process boot, not Unix epoch.

template<size_t N>
class MetricWindow {
public:
    explicit MetricWindow(int64_t bucket_width_sec = 1)
        : bucket_width_(bucket_width_sec)
    {
        int64_t now = current_sec();
        for (size_t i = 0; i < N; ++i)
            buckets_[i].reset(now - static_cast<int64_t>(N - i) * bucket_width_);
        head_ = N - 1;  // current bucket is the last initialized
    }

    // Record a value sample — thread-safe
    void record(double value, int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard<std::mutex> lk(mtx_);
        advance_to(ts_sec);
        buckets_[head_].add_sample(value);
    }

    // Record byte counters — thread-safe
    void record_bytes(uint64_t in, uint64_t out, int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard<std::mutex> lk(mtx_);
        advance_to(ts_sec);
        buckets_[head_].bytes_in  += in;
        buckets_[head_].bytes_out += out;
        ++buckets_[head_].count;
    }

    // Record a single event as an error — thread-safe
    void record_error(int64_t ts_sec = 0) {
        if (ts_sec == 0) ts_sec = current_sec();
        std::lock_guard<std::mutex> lk(mtx_);
        advance_to(ts_sec);
        ++buckets_[head_].errors;
        ++buckets_[head_].count;
    }

    // Read last `n_buckets` completed buckets (NOT including the current one)
    std::vector<MetricBucket> last(size_t n_buckets) const {
        std::lock_guard<std::mutex> lk(mtx_);
        n_buckets = std::min(n_buckets, N - 1);
        std::vector<MetricBucket> result;
        result.reserve(n_buckets);
        for (size_t i = n_buckets; i >= 1; --i) {
            size_t idx = (head_ + N - i) % N;
            result.push_back(buckets_[idx]);
        }
        return result;
    }

    // ── Summary ───────────────────────────────────────────────────────────────
    struct Summary {
        double   avg          = 0.0;
        double   min_val      = 0.0;
        double   max_val      = 0.0;
        uint64_t count        = 0;
        uint64_t bytes_in_total   = 0;
        uint64_t bytes_out_total  = 0;
        uint64_t errors_total     = 0;
        double   rate_per_sec     = 0.0;  // count / elapsed seconds
    };

    Summary summarize(size_t n_buckets) const {
        auto bkts = last(n_buckets);
        Summary s;
        s.min_val = std::numeric_limits<double>::max();
        double sum = 0.0;
        for (auto& b : bkts) {
            s.count           += b.count;
            s.bytes_in_total  += b.bytes_in;
            s.bytes_out_total += b.bytes_out;
            s.errors_total    += b.errors;
            if (b.count) {
                sum      += b.sum;
                s.min_val = std::min(s.min_val, b.min_val);
                s.max_val = std::max(s.max_val, b.max_val);
            }
        }
        if (s.count) s.avg = sum / s.count;
        double elapsed = static_cast<double>(bkts.size()) * bucket_width_;
        if (elapsed > 0) s.rate_per_sec = s.count / elapsed;
        if (s.min_val == std::numeric_limits<double>::max()) s.min_val = 0.0;
        return s;
    }

private:
    mutable std::mutex mtx_;
    std::array<MetricBucket, N> buckets_{};
    size_t  head_         = 0;
    int64_t bucket_width_ = 1;

    void advance_to(int64_t ts_sec) {
        int64_t current_start = buckets_[head_].timestamp_sec;
        if (current_start == 0) current_start = ts_sec;
        int64_t to_advance = (ts_sec - current_start) / bucket_width_;
        if (to_advance <= 0) return;

        for (int64_t i = 0; i < std::min(to_advance, static_cast<int64_t>(N)); ++i) {
            head_ = (head_ + 1) % N;
            buckets_[head_].reset(current_start + (i + 1) * bucket_width_);
        }
    }

    static int64_t current_sec() {
        // system_clock = wall-clock Unix time — matches pkt.timestamp_ns from libpcap
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ── Convenience aliases ───────────────────────────────────────────────────────
using Window1s   = MetricWindow<60>;   // 60 × 1s  = last 60 seconds
using Window10s  = MetricWindow<36>;   // 36 × 10s = last 6 minutes  (bucket_width=10)
using Window1min = MetricWindow<60>;   // 60 × 1m  = last hour       (bucket_width=60)
using Window1hr  = MetricWindow<24>;   // 24 × 1h  = last day        (bucket_width=3600)
