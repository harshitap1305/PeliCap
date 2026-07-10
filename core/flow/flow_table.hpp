#pragma once

#include <array>
#include <mutex>
#include <memory>
#include <vector>
#include <functional>
#include <absl/container/flat_hash_map.h>
#include "flow.hpp"
#include "flow_key.hpp"

// ── FlowTable ─────────────────────────────────────────────────────────────────
// Sharded hash map. 64 shards, each with its own mutex.
// Shard mutex is held only for lookup/insert — never during flow-field updates.
// Flow-field updates use the per-flow Flow::mtx_.

class FlowTable {
public:
    static constexpr size_t NUM_SHARDS = 64;

    using FlowPtr = std::shared_ptr<Flow>;

    struct ShardedEntry {
        mutable std::mutex mtx;
        absl::flat_hash_map<FlowKey, FlowPtr, FlowKeyHash> map;
    };

    // ── Lookup or create ─────────────────────────────────────────────────────
    // factory_fn() is called (without any lock held) only when the flow is new.
    // Returns nullptr if max_flows is reached and the key is unknown.
    FlowPtr get_or_create(const FlowKey& key,
                          std::function<FlowPtr()> factory_fn,
                          size_t max_flows) {
        auto& shard = get_shard(key);
        {
            std::lock_guard<std::mutex> lk(shard.mtx);
            auto it = shard.map.find(key);
            if (it != shard.map.end()) return it->second;

            // Memory guard — refuse new flows if table is full
            if (active_count_.load(std::memory_order_relaxed) >= max_flows) return nullptr;

            auto flow = factory_fn();
            shard.map.emplace(key, flow);
            active_count_.fetch_add(1, std::memory_order_relaxed);
            return flow;
        }
    }

    // ── Read-only lookup ─────────────────────────────────────────────────────
    FlowPtr find(const FlowKey& key) const {
        auto& shard = get_shard(key);
        std::lock_guard<std::mutex> lk(shard.mtx);
        auto it = shard.map.find(key);
        return (it != shard.map.end()) ? it->second : nullptr;
    }

    // ── Find by flow_id ──────────────────────────────────────────────────────
    // O(N) scan — only used by the REST API on demand, not the hot path.
    FlowPtr find_by_id(uint64_t flow_id) const {
        for (auto& shard : shards_) {
            std::lock_guard<std::mutex> lk(shard.mtx);
            for (auto& [k, f] : shard.map) {
                if (f->flow_id == flow_id) return f;
            }
        }
        return nullptr;
    }

    // ── Expiry sweep for one shard ────────────────────────────────────────────
    // Returns expired flows. Called by the expiry thread once per ~15ms.
    std::vector<FlowPtr> sweep_shard(size_t idx, int64_t now_ns) {
        std::vector<FlowPtr> expired;
        auto& shard = shards_[idx % NUM_SHARDS];
        std::lock_guard<std::mutex> lk(shard.mtx);
        for (auto it = shard.map.begin(); it != shard.map.end(); ) {
            if (it->second->expiry_ns < now_ns) {
                expired.push_back(it->second);
                // Use post-increment since absl::flat_hash_map::erase(it) might return void
                shard.map.erase(it++);
                active_count_.fetch_sub(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
        return expired;
    }

    // ── Remove a specific flow (on CLOSED/RESET) ─────────────────────────────
    void remove(const FlowKey& key) {
        auto& shard = get_shard(key);
        std::lock_guard<std::mutex> lk(shard.mtx);
        if (shard.map.erase(key) > 0) {
            active_count_.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // ── Snapshot all active flows for API listing ────────────────────────────
    std::vector<FlowPtr> snapshot() const {
        std::vector<FlowPtr> out;
        for (auto& shard : shards_) {
            std::lock_guard<std::mutex> lk(shard.mtx);
            out.reserve(out.size() + shard.map.size());
            for (auto& [k, f] : shard.map) out.push_back(f);
        }
        return out;
    }

    size_t total_active_flows() const {
        return active_count_.load(std::memory_order_relaxed);
    }

    void clear() {
        for (auto& shard : shards_) {
            std::lock_guard<std::mutex> lk(shard.mtx);
            shard.map.clear();
        }
        active_count_.store(0, std::memory_order_relaxed);
    }

private:
    std::array<ShardedEntry, NUM_SHARDS> shards_;
    std::atomic<size_t> active_count_{0};

    ShardedEntry& get_shard(const FlowKey& key) {
        size_t h = FlowKeyHash{}(key);
        return shards_[h & (NUM_SHARDS - 1)];
    }
    const ShardedEntry& get_shard(const FlowKey& key) const {
        size_t h = FlowKeyHash{}(key);
        return shards_[h & (NUM_SHARDS - 1)];
    }
};
