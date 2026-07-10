#pragma once
#include <array>
#include <cstdint>
#include <mutex>
#include <algorithm>
#include <limits>

// ── RttHistogram ──────────────────────────────────────────────────────────────
// Fixed-bucket histogram for TCP RTT in microseconds.
// Range: 0 – 2,000,000 µs (2000ms) with 1000µs (1ms) resolution (2000 buckets).
// Covers: LAN (<1ms), regional (10-50ms), cross-country (50-150ms),
//         international (150-400ms), high-latency (500ms-2s), and TCP retransmit outliers.
// RTTs above 2s go into the overflow bucket (last slot).
// Reset every 60s by the housekeeping thread to prevent stale data.

class RttHistogram {
public:
    static constexpr size_t   NUM_BUCKETS = 2000;
    static constexpr uint32_t BUCKET_US   = 1000;  // 1ms per bucket
    static constexpr uint32_t MAX_US      = NUM_BUCKETS * BUCKET_US;  // 2000ms = 2s

    void record(uint32_t latency_us) noexcept {
        std::lock_guard<std::mutex> lk(mtx_);
        size_t idx = std::min(static_cast<size_t>(latency_us / BUCKET_US), NUM_BUCKETS - 1);
        ++buckets_[idx];
        ++total_;
    }

    uint32_t p50() const { return percentile(0.50); }
    uint32_t p95() const { return percentile(0.95); }
    uint32_t p99() const { return percentile(0.99); }
    uint64_t count() const { std::lock_guard<std::mutex> lk(mtx_); return total_; }

    void reset() noexcept {
        std::lock_guard<std::mutex> lk(mtx_);
        buckets_.fill(0);
        total_ = 0;
    }

private:
    mutable std::mutex mtx_;
    std::array<uint64_t, NUM_BUCKETS> buckets_{};
    uint64_t total_ = 0;

    uint32_t percentile(double p) const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!total_) return 0;
        uint64_t target = static_cast<uint64_t>(total_ * p);
        uint64_t cumul  = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            cumul += buckets_[i];
            if (cumul >= target)
                return static_cast<uint32_t>(i * BUCKET_US);
        }
        return MAX_US;
    }
};

// ── HttpDnsHistogram ──────────────────────────────────────────────────────────
// Fixed-bucket histogram for DNS/HTTP latency in milliseconds.
// Range: 0 – 30,000 ms (30s) with 10ms resolution (3000 buckets).
// Covers: fast DNS (<10ms), typical DNS (50-200ms), slow DNS (1-5s),
//         and very slow/broken resolvers (up to 30s).
// Used for both DNS resolution time and HTTP response time.

class HttpDnsHistogram {
public:
    static constexpr size_t   NUM_BUCKETS = 3000;
    static constexpr uint32_t BUCKET_MS   = 10;    // 10ms per bucket
    static constexpr uint32_t MAX_MS      = NUM_BUCKETS * BUCKET_MS;  // 30s

    void record(uint32_t latency_ms) noexcept {
        std::lock_guard<std::mutex> lk(mtx_);
        size_t idx = std::min(static_cast<size_t>(latency_ms / BUCKET_MS), NUM_BUCKETS - 1);
        ++buckets_[idx];
        ++total_;
    }

    uint32_t p50() const { return percentile(0.50); }
    uint32_t p95() const { return percentile(0.95); }
    uint32_t p99() const { return percentile(0.99); }
    uint64_t count() const { std::lock_guard<std::mutex> lk(mtx_); return total_; }

    void reset() noexcept {
        std::lock_guard<std::mutex> lk(mtx_);
        buckets_.fill(0);
        total_ = 0;
    }

private:
    mutable std::mutex mtx_;
    std::array<uint64_t, NUM_BUCKETS> buckets_{};
    uint64_t total_ = 0;

    uint32_t percentile(double p) const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!total_) return 0;
        uint64_t target = static_cast<uint64_t>(total_ * p);
        uint64_t cumul  = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            cumul += buckets_[i];
            if (cumul >= target)
                return static_cast<uint32_t>(i * BUCKET_MS);
        }
        return MAX_MS;
    }
};
