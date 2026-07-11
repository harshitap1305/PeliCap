#pragma once
#include <unordered_map>
#include <string>
#include <mutex>
#include <cstdint>
#include <chrono>
#include <atomic>

// ── CooldownTracker ───────────────────────────────────────────────────────────
// Prevents alert storms by enforcing a per-key fire interval.
// Key format: "ALERT_TYPE:context_key" e.g. "TCP_HIGH_RTT:192.168.1.10"
//
// Also implements global maintenance suppression windows:
//   suppress(duration_ns) → silences ALL alerts until the window expires.

class CooldownTracker {
public:
    explicit CooldownTracker(int64_t default_cooldown_ns = 60'000'000'000LL)
        : default_cooldown_ns_(default_cooldown_ns) {}

    // Returns true if this alert key is allowed to fire now.
    // Records the fire time on success.
    bool can_fire(const std::string& key, int64_t now_ns,
                  int64_t cooldown_override_ns = -1) {
        // Check global suppression first
        if (suppressed_until_ns_ > 0 && now_ns < suppressed_until_ns_)
            return false;

        std::lock_guard<std::mutex> lk(mtx_);
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

    // Force-reset a key's cooldown — called when a condition resolves
    void reset(const std::string& key) {
        std::lock_guard<std::mutex> lk(mtx_);
        last_fire_.erase(key);
    }

    // Suppress ALL alerts for duration_ns nanoseconds (maintenance window)
    void suppress(int64_t duration_ns) {
        int64_t now = now_ns();
        suppressed_until_ns_.store(now + duration_ns, std::memory_order_release);
    }

    // True if currently in a maintenance suppression window
    bool is_suppressed() const {
        return suppressed_until_ns_.load(std::memory_order_acquire) > now_ns();
    }

    int64_t suppressed_until_ns() const {
        return suppressed_until_ns_.load(std::memory_order_acquire);
    }

    // Remove stale keys to prevent unbounded map growth
    void evict_old(int64_t now_ns, int64_t max_age_ns = 600'000'000'000LL) {
        std::lock_guard<std::mutex> lk(mtx_);
        for (auto it = last_fire_.begin(); it != last_fire_.end(); ) {
            if (now_ns - it->second > max_age_ns)
                it = last_fire_.erase(it);
            else
                ++it;
        }
    }

    size_t active_keys() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return last_fire_.size();
    }

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, int64_t> last_fire_;
    int64_t default_cooldown_ns_;
    std::atomic<int64_t> suppressed_until_ns_{0};

    static int64_t now_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};
