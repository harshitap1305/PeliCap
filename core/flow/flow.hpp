#pragma once

#include <cstdint>
#include <string>
#include <mutex>
#include <algorithm>
#include "flow_key.hpp"
#include "../dissector/parsed_packet.hpp"

// ── TCP State Machine ─────────────────────────────────────────────────────────
enum class TcpFlowState : uint8_t {
    INIT        = 0,  // No packets seen yet
    SYN_SENT    = 1,  // SYN seen (client→server)
    SYN_RCVD    = 2,  // SYN-ACK seen (server→client)
    ESTABLISHED = 3,  // Final ACK seen
    MID_STREAM  = 4,  // Capture started mid-connection (no SYN seen)
    FIN_WAIT    = 5,  // FIN seen from one side
    TIME_WAIT   = 6,  // Both FINs seen
    CLOSED      = 7,  // Clean close confirmed
    RESET       = 8,  // RST seen
    EXPIRED     = 9,  // Idle timeout — no FIN/RST
};

inline const char* tcp_state_str(TcpFlowState s) {
    switch (s) {
        case TcpFlowState::INIT:        return "INIT";
        case TcpFlowState::SYN_SENT:    return "SYN_SENT";
        case TcpFlowState::SYN_RCVD:    return "SYN_RCVD";
        case TcpFlowState::ESTABLISHED: return "ESTABLISHED";
        case TcpFlowState::MID_STREAM:  return "MID_STREAM";
        case TcpFlowState::FIN_WAIT:    return "FIN_WAIT";
        case TcpFlowState::TIME_WAIT:   return "TIME_WAIT";
        case TcpFlowState::CLOSED:      return "CLOSED";
        case TcpFlowState::RESET:       return "RESET";
        case TcpFlowState::EXPIRED:     return "EXPIRED";
        default:                        return "UNKNOWN";
    }
}

// ── RttTracker ────────────────────────────────────────────────────────────────
// Fixed ring buffer of 32 RTT samples in microseconds.
// No heap allocation — predictable size regardless of packet count.
struct RttTracker {
    static constexpr uint8_t MAX = 32;
    uint32_t samples[MAX] = {};
    uint8_t  head  = 0;
    uint8_t  count = 0;

    void add(uint32_t rtt_us) noexcept {
        if (rtt_us == 0 || rtt_us > 60'000'000u) return;  // sanity: 0 < rtt < 60s
        samples[head % MAX] = rtt_us;
        head = (head + 1) % MAX;
        if (count < MAX) ++count;
    }
    uint32_t avg() const noexcept {
        if (!count) return 0;
        uint64_t sum = 0;
        for (uint8_t i = 0; i < count; ++i) sum += samples[i];
        return static_cast<uint32_t>(sum / count);
    }
    uint32_t min() const noexcept {
        if (!count) return 0;
        uint32_t m = samples[0];
        for (uint8_t i = 1; i < count; ++i) m = std::min(m, samples[i]);
        return m;
    }
    uint32_t p95() const noexcept {
        if (!count) return 0;
        uint32_t copy[MAX];
        std::copy(samples, samples + count, copy);
        std::sort(copy, copy + count);
        return copy[static_cast<int>(count * 0.95f)];
    }
};

// ── RetransmitTracker ─────────────────────────────────────────────────────────
// Circular window of last 64 seq numbers seen. O(64) lookup per data packet.
struct RetransmitTracker {
    static constexpr uint8_t WINDOW = 64;
    uint32_t seqs[WINDOW] = {};
    uint8_t  head  = 0;
    uint32_t count = 0;  // total retransmit count

    bool see_seq(uint32_t seq, uint16_t payload_len) noexcept {
        if (payload_len == 0) return false;  // ACK-only — not a retransmit
        // Check if already seen
        for (uint8_t i = 0; i < WINDOW; ++i) {
            if (seqs[i] == seq && seq != 0) {
                ++count;
                return true;
            }
        }
        seqs[head % WINDOW] = seq;
        head = (head + 1) % WINDOW;
        return false;
    }
};

// ── DnsRttTracker ─────────────────────────────────────────────────────────────
// Matches DNS queries to responses by transaction ID to compute RTT.
struct DnsRttEntry { uint16_t txid = 0; int64_t send_ns = 0; bool valid = false; };

struct DnsRttTracker {
    DnsRttEntry entries[8] = {};
    uint8_t head = 0;

    void record_query(uint16_t txid, int64_t ns) noexcept {
        entries[head % 8] = {txid, ns, true};
        head = (head + 1) % 8;
    }
    int64_t match_response(uint16_t txid) noexcept {
        for (auto& e : entries) {
            if (e.valid && e.txid == txid) {
                e.valid = false;
                return e.send_ns;
            }
        }
        return -1;
    }
};

// ── TsRttTracker ──────────────────────────────────────────────────────────────
// Matches TCP timestamp values to their send time for precise per-segment RTT.
struct TsRttEntry { uint32_t ts_val = 0; int64_t send_ns = 0; bool valid = false; };

struct TsRttTracker {
    TsRttEntry entries[8] = {};
    uint8_t head = 0;

    void record(uint32_t ts_val, int64_t ns) noexcept {
        entries[head % 8] = {ts_val, ns, true};
        head = (head + 1) % 8;
    }
    int64_t match_ecr(uint32_t ts_ecr) noexcept {
        for (auto& e : entries) {
            if (e.valid && e.ts_val == ts_ecr) {
                e.valid = false;
                return e.send_ns;
            }
        }
        return -1;
    }
};

// ── Flow ──────────────────────────────────────────────────────────────────────
// ~650 bytes. Fixed-size — no std::vector growth, predictable memory at scale.
struct Flow {
    mutable std::mutex mtx_;  // per-flow lock — dropped shard lock before taking this

    // ── Identity ─────────────────────────────────────────────────────────────
    uint64_t    flow_id  = 0;
    FlowKey     key;
    std::string src_ip_str, dst_ip_str;
    uint16_t    src_port = 0, dst_port = 0;
    uint8_t     protocol = 0;
    bool        is_ipv6  = false;
    std::string interface_name;
    std::string session_id;

    // ── Timing ───────────────────────────────────────────────────────────────
    int64_t start_time_ns = 0;  // first packet (packet timestamp)
    int64_t last_seen_ns  = 0;  // last packet (packet timestamp)
    int64_t expiry_ns     = 0;  // wall-clock monotonic — when to evict

    // ── Packet / byte counters ────────────────────────────────────────────────
    uint64_t fwd_packets        = 0;  // flow.src → flow.dst
    uint64_t rev_packets        = 0;  // flow.dst → flow.src
    uint64_t fwd_bytes          = 0;
    uint64_t rev_bytes          = 0;
    uint64_t payload_bytes      = 0;  // bytes excluding all headers
    uint64_t prev_metrics_bytes = 0;  // last total_bytes() snapshot — used by MetricsEngine to compute delta

    // ── TCP state ─────────────────────────────────────────────────────────────
    TcpFlowState tcp_state    = TcpFlowState::INIT;
    uint32_t     client_isn   = 0;
    uint32_t     server_isn   = 0;
    uint8_t      fin_count    = 0;
    uint8_t      window_scale_client = 0;
    uint8_t      window_scale_server = 0;
    int64_t      syn_time_ns  = 0;   // time of first SYN (for setup-time calc)

    // ── Quality metrics ───────────────────────────────────────────────────────
    uint32_t     handshake_rtt_us       = 0;   // SYN→SYN-ACK delta (one-way RTT)
    uint32_t     connection_setup_us    = 0;   // SYN→ACK (3-way handshake complete)
    RttTracker   rtt;                          // ongoing per-segment RTT samples
    RetransmitTracker retransmit;
    DnsRttTracker     dns_rtt;
    TsRttTracker      ts_rtt;
    uint32_t     zero_window_events = 0;
    uint32_t     dup_ack_count      = 0;
    uint32_t     last_ack_fwd       = 0;       // last ACK num seen in fwd direction
    uint32_t     last_ack_rev       = 0;
    uint8_t      dup_ack_streak_fwd = 0;       // consecutive dup-ACK counter
    uint8_t      dup_ack_streak_rev = 0;

    // ── Application layer ─────────────────────────────────────────────────────
    AppProtocol app_protocol       = AppProtocol::Unknown;
    std::string tls_sni;
    std::string http_host;
    std::string dns_query;
    uint32_t    http_request_count        = 0;
    uint32_t    http_response_count       = 0;
    uint32_t    dns_transaction_count     = 0;
    int64_t     http_request_first_seen_ns = 0;  // timestamp of first HTTP request — for latency calc

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    bool is_active  = true;
    bool was_closed = false;  // saw FIN or RST

    // ── Helpers ───────────────────────────────────────────────────────────────
    uint64_t total_packets() const noexcept { return fwd_packets + rev_packets; }
    uint64_t total_bytes()   const noexcept { return fwd_bytes   + rev_bytes;   }
    int64_t  duration_ns()   const noexcept { return last_seen_ns - start_time_ns; }
};
