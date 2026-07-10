#pragma once

#include "flow.hpp"
#include <nlohmann/json.hpp>
#include <string>

// ── Helpers ───────────────────────────────────────────────────────────────────

inline std::string proto_str(uint8_t p) {
    switch (p) {
        case 6:  return "TCP";
        case 17: return "UDP";
        case 1:  return "ICMP";
        case 58: return "ICMPv6";
        default: return std::to_string(p);
    }
}

// ── Full detail — for GET /api/flows/{id} ─────────────────────────────────────

inline nlohmann::json flow_to_json(const Flow& f) {
    nlohmann::json j;

    // Identity
    j["flow_id"]       = f.flow_id;
    j["src"]           = f.src_ip_str + ":" + std::to_string(f.src_port);
    j["dst"]           = f.dst_ip_str + ":" + std::to_string(f.dst_port);
    j["src_ip"]        = f.src_ip_str;
    j["dst_ip"]        = f.dst_ip_str;
    j["src_port"]      = f.src_port;
    j["dst_port"]      = f.dst_port;
    j["protocol"]      = proto_str(f.protocol);
    j["is_ipv6"]       = f.is_ipv6;
    j["interface"]     = f.interface_name;
    j["app_protocol"]  = app_protocol_str(f.app_protocol);

    // Timing
    j["start_ns"]      = f.start_time_ns;
    j["duration_ms"]   = f.duration_ns() / 1'000'000;

    // Counters
    j["fwd_packets"]   = f.fwd_packets;
    j["rev_packets"]   = f.rev_packets;
    j["fwd_bytes"]     = f.fwd_bytes;
    j["rev_bytes"]     = f.rev_bytes;
    j["payload_bytes"] = f.payload_bytes;
    j["total_packets"] = f.total_packets();
    j["total_bytes"]   = f.total_bytes();

    // TCP state
    if (f.protocol == 6) {
        j["tcp_state"]          = tcp_state_str(f.tcp_state);
        j["handshake_rtt_us"]   = f.handshake_rtt_us;
        j["setup_time_us"]      = f.connection_setup_us;
        j["window_scale_client"]= f.window_scale_client;
        j["window_scale_server"]= f.window_scale_server;
    }

    // Quality metrics
    j["avg_rtt_us"]    = f.rtt.avg();
    j["min_rtt_us"]    = f.rtt.min();
    j["p95_rtt_us"]    = f.rtt.p95();
    j["retransmits"]   = f.retransmit.count;
    j["zero_windows"]  = f.zero_window_events;
    j["dup_acks"]      = f.dup_ack_count;

    // Application layer
    if (!f.tls_sni.empty())   j["sni"]        = f.tls_sni;
    if (!f.http_host.empty()) j["http_host"]   = f.http_host;
    if (!f.dns_query.empty()) j["dns_query"]   = f.dns_query;
    if (f.http_request_count  > 0) j["http_requests"]  = f.http_request_count;
    if (f.http_response_count > 0) j["http_responses"] = f.http_response_count;
    if (f.dns_transaction_count > 0) j["dns_transactions"] = f.dns_transaction_count;

    // Lifecycle
    j["active"]      = f.is_active;
    j["closed"]      = f.was_closed;

    return j;
}

// ── Summary — for GET /api/flows list ─────────────────────────────────────────
// Lightweight: omits RTT samples, SACK info, per-segment detail.

inline nlohmann::json flow_to_summary_json(const Flow& f) {
    nlohmann::json j;
    j["flow_id"]      = f.flow_id;
    j["src"]          = f.src_ip_str + ":" + std::to_string(f.src_port);
    j["dst"]          = f.dst_ip_str + ":" + std::to_string(f.dst_port);
    j["protocol"]     = proto_str(f.protocol);
    j["app_protocol"] = app_protocol_str(f.app_protocol);
    j["duration_ms"]  = f.duration_ns() / 1'000'000;
    j["total_bytes"]  = f.total_bytes();
    j["total_packets"]= f.total_packets();
    j["avg_rtt_us"]   = f.rtt.avg();
    j["retransmits"]  = f.retransmit.count;

    if (f.protocol == 6)
        j["tcp_state"] = tcp_state_str(f.tcp_state);

    if (!f.tls_sni.empty())   j["sni"]      = f.tls_sni;
    if (!f.http_host.empty()) j["http_host"] = f.http_host;
    if (!f.dns_query.empty()) j["dns_query"] = f.dns_query;

    return j;
}
