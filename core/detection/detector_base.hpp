#pragma once
#include "alert.hpp"
#include "alert_store.hpp"
#include "cooldown_tracker.hpp"
#include "ewma_baseline.hpp"
#include <functional>
#include <atomic>
#include <chrono>
#include <string>
#include <nlohmann/json.hpp>

// ── DetectorBase ──────────────────────────────────────────────────────────────
// Base class for all detectors. Provides:
//   - Cooldown enforcement (per-key)
//   - EWMA baseline tracking
//   - Monotonic alert_id assignment (inline static atomic, no ODR issue)
//   - Dynamic vs. static threshold selection
//
// Subclasses implement evaluate() or on_flow_event() and call fire() when
// a condition is detected.

class DetectorBase {
public:
    struct Config {
        bool   enabled              = true;
        double static_threshold     = 0.0;  // used during EWMA warmup (<10 samples)
        double sigma_multiplier     = 3.0;  // dynamic threshold = baseline + N*sigma
        int64_t cooldown_ns         = 60'000'000'000LL;  // 60s default
        bool   use_dynamic_threshold = true;
    };

    DetectorBase(Config cfg, AlertStore& store, CooldownTracker& cooldown)
        : config_(cfg), store_(store), cooldown_(cooldown) {}

    virtual ~DetectorBase() = default;

    bool is_enabled()  const { return config_.enabled; }
    void set_enabled(bool v)  { config_.enabled = v; }
    void set_threshold(double t) { config_.static_threshold = t; }
    void set_sigma(double s)     { config_.sigma_multiplier = s; }
    void set_cooldown_ns(int64_t ns) { config_.cooldown_ns = ns; }

    double current_baseline() const { return ewma_.get(); }
    double current_stddev()   const { return ewma_.stddev(); }
    uint64_t sample_count()   const { return ewma_.sample_count(); }
    bool baseline_ready()     const { return ewma_.ready(); }

    nlohmann::json status_json() const {
        return {
            {"enabled",           config_.enabled},
            {"static_threshold",  config_.static_threshold},
            {"sigma_multiplier",  config_.sigma_multiplier},
            {"cooldown_sec",      config_.cooldown_ns / 1'000'000'000LL},
            {"baseline",          ewma_.get()},
            {"stddev",            ewma_.stddev()},
            {"sample_count",      ewma_.sample_count()},
            {"baseline_ready",    ewma_.ready()},
            {"effective_threshold", effective_threshold()}
        };
    }

    EwmaBaseline& baseline() { return ewma_; }  // for persistence export/import

protected:
    // Call this from subclass when a condition is detected.
    // Enforces cooldown, assigns alert_id, sets timestamp, pushes to store.
    void fire(Alert alert, const std::string& cooldown_key) {
        if (!config_.enabled) return;
        int64_t now = now_ns();
        if (!cooldown_.can_fire(cooldown_key, now, config_.cooldown_ns)) return;

        alert.alert_id    = next_id_.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp_ns = now;
        alert.is_ongoing  = true;

        store_.push(std::move(alert));
    }

    // Returns the effective threshold — dynamic if baseline is ready,
    // static fallback during warmup (<10 samples).
    double effective_threshold() const {
        if (config_.use_dynamic_threshold && ewma_.ready())
            return ewma_.dynamic_threshold(config_.sigma_multiplier,
                                           config_.static_threshold);
        return config_.static_threshold;
    }

    void update_baseline(double value) { ewma_.update(value); }

    static int64_t now_ns() {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }

    Config          config_;
    AlertStore&     store_;
    CooldownTracker& cooldown_;
    EwmaBaseline    ewma_;

private:
    // inline static: C++17 — defined once across all TUs, no ODR violation
    inline static std::atomic<uint64_t> next_id_{1};
};
