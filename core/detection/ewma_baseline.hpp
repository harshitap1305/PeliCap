#pragma once
#include <cstdint>
#include <cmath>
#include <mutex>
#include <limits>
#include <nlohmann/json.hpp>

// ── EwmaBaseline ──────────────────────────────────────────────────────────────
// Exponentially Weighted Moving Average with correct Welford variance tracking.
//
// Two-track design:
//   value_    = EWMA of observed samples (fast-responding adaptive baseline)
//   mean_     = Welford arithmetic mean  (stable base for variance computation)
//   variance_ = Welford M2 accumulator  (exact running variance, no bias)
//
// Dynamic threshold = EWMA + sigma_multiplier × sqrt(M2 / count)
//
// Warmup: first 10 samples use static_threshold (caller provides it).
// After 10 samples: dynamic threshold activates automatically.
//
// Persistence: export_state() / import_state() for baseline survival across
// container restarts (written to /app/baselines.json on shutdown).

class EwmaBaseline {
public:
    // alpha: smoothing factor — 0.1 = slow/stable, 0.3 = fast/reactive
    explicit EwmaBaseline(double alpha = 0.1)
        : alpha_(alpha) {}

    void update(double new_value) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!initialized_) {
            value_       = new_value;
            mean_        = new_value;
            initialized_ = true;
            count_       = 1;
            return;
        }
        // Update EWMA
        value_ = alpha_ * new_value + (1.0 - alpha_) * value_;

        // Update Welford mean + M2 (online variance, numerically stable)
        ++count_;
        double old_mean = mean_;
        mean_          += (new_value - mean_) / static_cast<double>(count_);
        variance_      += (new_value - old_mean) * (new_value - mean_);
    }

    // Current EWMA baseline value
    double get() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return initialized_ ? value_ : 0.0;
    }

    // True once 10+ samples have been recorded — dynamic threshold reliable
    bool ready() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return initialized_ && count_ >= 10;
    }

    uint64_t sample_count() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return count_;
    }

    // stddev from Welford M2 accumulator
    double stddev() const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (count_ < 2) return 0.0;
        return std::sqrt(variance_ / static_cast<double>(count_));
    }

    // Dynamic threshold: baseline + N standard deviations above normal
    // Falls back to static_fallback if not yet warmed up.
    double dynamic_threshold(double sigma_multiplier,
                             double static_fallback) const {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!initialized_ || count_ < 10)
            return static_fallback;
        double sd = count_ < 2 ? 0.0 : std::sqrt(variance_ / static_cast<double>(count_));
        return value_ + sigma_multiplier * sd;
    }

    // ── Persistence ───────────────────────────────────────────────────────────
    nlohmann::json export_state() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return {
            {"alpha",       alpha_},
            {"value",       value_},
            {"mean",        mean_},
            {"variance",    variance_},
            {"count",       count_},
            {"initialized", initialized_}
        };
    }

    void import_state(const nlohmann::json& j) {
        std::lock_guard<std::mutex> lk(mtx_);
        try {
            alpha_       = j.at("alpha").get<double>();
            value_       = j.at("value").get<double>();
            mean_        = j.at("mean").get<double>();
            variance_    = j.at("variance").get<double>();
            count_       = j.at("count").get<uint64_t>();
            initialized_ = j.at("initialized").get<bool>();
        } catch (...) { /* ignore stale/corrupt baseline */ }
    }

private:
    mutable std::mutex mtx_;
    double   alpha_;
    double   value_       = 0.0;  // EWMA
    double   mean_        = 0.0;  // Welford arithmetic mean
    double   variance_    = 0.0;  // Welford M2 accumulator
    uint64_t count_       = 0;
    bool     initialized_ = false;
};
