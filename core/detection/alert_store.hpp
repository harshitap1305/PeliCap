#pragma once
#include "alert.hpp"
#include <deque>
#include <vector>
#include <mutex>
#include <functional>
#include <cstddef>

// ── AlertStore ────────────────────────────────────────────────────────────────
// Thread-safe in-memory ring buffer of the last N alerts.
// Optionally calls a persistence callback (PostgreSQL) on each push.
// All REST API alert queries go through this class.

class AlertStore {
public:
    explicit AlertStore(size_t max_in_memory = 10000)
        : max_size_(max_in_memory) {}

    // Push a new alert — called by DetectorBase::fire()
    void push(Alert alert) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (alerts_.size() >= max_size_)
            alerts_.pop_front();
        alerts_.push_back(alert);
        for (auto& cb : callbacks_) {
            cb(alerts_.back());
        }
    }

    // Most recent N alerts, newest-first, optional minimum severity filter
    std::vector<Alert> recent(size_t n = 100,
                              AlertSeverity min_sev = AlertSeverity::INFO) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<Alert> result;
        result.reserve(std::min(n, alerts_.size()));
        for (auto it = alerts_.rbegin();
             it != alerts_.rend() && result.size() < n; ++it) {
            if (it->severity >= min_sev)
                result.push_back(*it);
        }
        return result;
    }

    // Alerts filtered by type, newest-first
    std::vector<Alert> by_type(AlertType type, size_t n = 50) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<Alert> result;
        for (auto it = alerts_.rbegin();
             it != alerts_.rend() && result.size() < n; ++it) {
            if (it->type == type)
                result.push_back(*it);
        }
        return result;
    }

    // Count by severity in last N seconds (n_sec=0 = all time)
    struct SeverityCount { size_t info = 0; size_t warning = 0; size_t critical = 0; };
    SeverityCount count_recent(int64_t since_ns = 0) const {
        std::lock_guard<std::mutex> lk(mtx_);
        SeverityCount c;
        for (auto& a : alerts_) {
            if (since_ns > 0 && a.timestamp_ns < since_ns) continue;
            switch (a.severity) {
                case AlertSeverity::INFO:     ++c.info;     break;
                case AlertSeverity::WARNING:  ++c.warning;  break;
                case AlertSeverity::CRITICAL: ++c.critical; break;
            }
        }
        return c;
    }

    // Get the 5 most recent alerts to a given dst_ip for correlation
    std::vector<Alert> recent_to_dst(const std::string& dst_ip, size_t n = 5) const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<Alert> result;
        for (auto it = alerts_.rbegin();
             it != alerts_.rend() && result.size() < n; ++it) {
            if (it->context.dst_ip == dst_ip)
                result.push_back(*it);
        }
        return result;
    }

    size_t count() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return alerts_.size();
    }

    // Register callback — called on every push (e.g. for PG and WebSockets)
    void add_callback(std::function<void(const Alert&)> cb) {
        std::lock_guard<std::mutex> lk(mtx_);
        callbacks_.push_back(std::move(cb));
    }

private:
    mutable std::mutex mtx_;
    std::deque<Alert>  alerts_;
    size_t             max_size_;
    std::vector<std::function<void(const Alert&)>> callbacks_;
};
