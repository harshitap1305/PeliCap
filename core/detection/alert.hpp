#pragma once
#include <cstdint>
#include <string>
#include <chrono>
#include <nlohmann/json.hpp>

// ── AlertSeverity ─────────────────────────────────────────────────────────────
enum class AlertSeverity : uint8_t {
    INFO     = 0,   // informational — worth logging, no action needed
    WARNING  = 1,   // degraded performance — investigate
    CRITICAL = 2,   // service impact — act now
};

inline const char* severity_str(AlertSeverity s) {
    switch (s) {
        case AlertSeverity::INFO:     return "INFO";
        case AlertSeverity::WARNING:  return "WARNING";
        case AlertSeverity::CRITICAL: return "CRITICAL";
        default:                      return "UNKNOWN";
    }
}

// ── AlertType ─────────────────────────────────────────────────────────────────
enum class AlertType : uint16_t {
    // TCP quality
    TCP_RETRANSMISSION_SPIKE  = 100,
    TCP_ZERO_WINDOW           = 101,
    TCP_HIGH_RTT              = 102,
    TCP_LONG_LIVED_CONNECTION = 103,
    // DNS
    DNS_HIGH_LATENCY          = 200,
    DNS_NXDOMAIN_SPIKE        = 201,
    DNS_QUERY_FLOOD           = 202,
    // HTTP
    HTTP_ERROR_RATE_SPIKE     = 300,
    HTTP_LATENCY_SPIKE        = 301,
    HTTP_REQUEST_FLOOD        = 302,
    // Network / traffic
    TRAFFIC_SPIKE             = 400,
    TRAFFIC_DROP              = 401,
    // Behavioral
    PORT_SCAN                 = 500,
    HOST_SCAN                 = 501,
    LARGE_FLOW                = 600,
};

inline const char* alert_type_str(AlertType t) {
    switch (t) {
        case AlertType::TCP_RETRANSMISSION_SPIKE:  return "TCP_RETRANSMISSION_SPIKE";
        case AlertType::TCP_ZERO_WINDOW:           return "TCP_ZERO_WINDOW";
        case AlertType::TCP_HIGH_RTT:              return "TCP_HIGH_RTT";
        case AlertType::TCP_LONG_LIVED_CONNECTION: return "TCP_LONG_LIVED_CONNECTION";
        case AlertType::DNS_HIGH_LATENCY:          return "DNS_HIGH_LATENCY";
        case AlertType::DNS_NXDOMAIN_SPIKE:        return "DNS_NXDOMAIN_SPIKE";
        case AlertType::DNS_QUERY_FLOOD:           return "DNS_QUERY_FLOOD";
        case AlertType::HTTP_ERROR_RATE_SPIKE:     return "HTTP_ERROR_RATE_SPIKE";
        case AlertType::HTTP_LATENCY_SPIKE:        return "HTTP_LATENCY_SPIKE";
        case AlertType::HTTP_REQUEST_FLOOD:        return "HTTP_REQUEST_FLOOD";
        case AlertType::TRAFFIC_SPIKE:             return "TRAFFIC_SPIKE";
        case AlertType::TRAFFIC_DROP:              return "TRAFFIC_DROP";
        case AlertType::PORT_SCAN:                 return "PORT_SCAN";
        case AlertType::HOST_SCAN:                 return "HOST_SCAN";
        case AlertType::LARGE_FLOW:                return "LARGE_FLOW";
        default:                                   return "UNKNOWN";
    }
}

// ── AlertContext ──────────────────────────────────────────────────────────────
// Populated per-alert — not all fields used by every type.
struct AlertContext {
    std::string  src_ip;
    std::string  dst_ip;
    uint16_t     src_port       = 0;
    uint16_t     dst_port       = 0;
    std::string  domain;         // DNS alerts
    std::string  endpoint;       // HTTP alerts
    std::string  protocol;
    std::string  extra;          // freeform detail string
    double       observed_value  = 0.0;
    double       threshold_value = 0.0;
    double       baseline_value  = 0.0;
    uint64_t     flow_id         = 0;
    uint32_t     affected_flows  = 0;
};

// ── Alert ─────────────────────────────────────────────────────────────────────
struct Alert {
    uint64_t       alert_id       = 0;   // assigned by DetectorBase::fire()
    AlertType      type           = AlertType::TRAFFIC_SPIKE;
    AlertSeverity  severity       = AlertSeverity::INFO;
    int64_t        timestamp_ns   = 0;   // set by fire()
    std::string    title;
    std::string    description;
    AlertContext   context;
    bool           is_ongoing     = true;
    int64_t        resolved_at_ns = 0;   // 0 = still active
    uint64_t       correlation_id = 0;   // groups related concurrent alerts

    nlohmann::json to_json() const {
        nlohmann::json j;
        j["alert_id"]     = alert_id;
        j["type"]         = alert_type_str(type);
        j["type_code"]    = static_cast<int>(type);
        j["severity"]     = severity_str(severity);
        j["timestamp_ns"] = timestamp_ns;
        j["title"]        = title;
        j["description"]  = description;
        j["is_ongoing"]   = is_ongoing;
        j["observed"]     = context.observed_value;
        j["threshold"]    = context.threshold_value;
        j["baseline"]     = context.baseline_value;
        if (!context.src_ip.empty())   j["src_ip"]   = context.src_ip;
        if (!context.dst_ip.empty())   j["dst_ip"]   = context.dst_ip;
        if (!context.domain.empty())   j["domain"]   = context.domain;
        if (!context.endpoint.empty()) j["endpoint"] = context.endpoint;
        if (!context.extra.empty())    j["extra"]    = context.extra;
        if (context.flow_id > 0)       j["flow_id"]  = context.flow_id;
        if (correlation_id > 0)        j["correlation_id"] = correlation_id;
        return j;
    }
};
