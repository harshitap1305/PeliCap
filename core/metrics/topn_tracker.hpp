#pragma once
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <string>
#include <mutex>
#include <cstdint>

// ── TopNTracker<Key> ──────────────────────────────────────────────────────────
// Tracks top-N entries by count (bytes, requests) or average latency.
// Uses partial_sort for O(N log k) query — acceptable since N is bounded.
// Evicts bottom 10% when the map exceeds max_keys to prevent OOM.
// Reset every 60s by the housekeeping thread for rolling windows.

template<typename Key>
class TopNTracker {
public:
    struct Entry {
        Key      key;
        uint64_t value = 0;   // count or bytes
        double   avg   = 0.0; // average latency (when used for latency top-N)
        uint64_t count = 0;   // number of samples (for latency avg)
    };

    explicit TopNTracker(size_t max_keys = 10000) : max_keys_(max_keys) {}

    // Increment count/bytes for a key
    void increment(const Key& key, uint64_t delta = 1) {
        std::lock_guard<std::mutex> lk(mtx_);
        counts_[key] += delta;
        if (counts_.size() > max_keys_) evict_bottom_10pct();
    }

    // Record a latency observation for a key
    void record_latency(const Key& key, double latency_ms) {
        std::lock_guard<std::mutex> lk(mtx_);
        auto& e = latencies_[key];
        e.sum   += latency_ms;
        e.count += 1;
        if (latencies_.size() > max_keys_) evict_latency_bottom_10pct();
    }

    // Get top N entries by count/bytes value
    std::vector<Entry> top_by_count(size_t n) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<Entry> result;
        result.reserve(counts_.size());
        for (auto& [k, v] : counts_)
            result.push_back({k, v, 0.0, v});
        size_t take = std::min(n, result.size());
        std::partial_sort(result.begin(), result.begin() + take, result.end(),
            [](const Entry& a, const Entry& b) { return a.value > b.value; });
        result.resize(take);
        return result;
    }

    // Get top N entries by average latency (highest = slowest)
    std::vector<Entry> top_by_avg_latency(size_t n) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<Entry> result;
        result.reserve(latencies_.size());
        for (auto& [k, e] : latencies_) {
            double avg = e.count ? e.sum / e.count : 0.0;
            result.push_back({k, e.count, avg, e.count});
        }
        size_t take = std::min(n, result.size());
        std::partial_sort(result.begin(), result.begin() + take, result.end(),
            [](const Entry& a, const Entry& b) { return a.avg > b.avg; });
        result.resize(take);
        return result;
    }

    // Reset all data — called every 60s by housekeeping for rolling windows
    void reset() {
        std::lock_guard<std::mutex> lk(mtx_);
        counts_.clear();
        latencies_.clear();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return counts_.size() + latencies_.size();
    }

private:
    struct LatencyAccum { double sum = 0.0; uint64_t count = 0; };

    mutable std::mutex mtx_;
    std::unordered_map<Key, uint64_t>       counts_;
    std::unordered_map<Key, LatencyAccum>   latencies_;
    size_t max_keys_;

    // Remove bottom 10% by count value when map is full
    void evict_bottom_10pct() {
        std::vector<uint64_t> vals;
        vals.reserve(counts_.size());
        for (auto& [k, v] : counts_) vals.push_back(v);
        std::nth_element(vals.begin(), vals.begin() + vals.size() / 10, vals.end());
        uint64_t threshold = vals[vals.size() / 10];
        for (auto it = counts_.begin(); it != counts_.end(); ) {
            if (it->second <= threshold) it = counts_.erase(it);
            else ++it;
        }
    }

    void evict_latency_bottom_10pct() {
        std::vector<double> avgs;
        avgs.reserve(latencies_.size());
        for (auto& [k, e] : latencies_)
            avgs.push_back(e.count ? e.sum / e.count : 0.0);
        std::nth_element(avgs.begin(), avgs.begin() + avgs.size() / 10, avgs.end());
        double threshold = avgs[avgs.size() / 10];
        for (auto it = latencies_.begin(); it != latencies_.end(); ) {
            double avg = it->second.count ? it->second.sum / it->second.count : 0.0;
            if (avg <= threshold) it = latencies_.erase(it);
            else ++it;
        }
    }
};
