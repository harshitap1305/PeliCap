#pragma once

#include <thread>
#include <atomic>
#include <functional>
#include <chrono>
#include "flow_table.hpp"
#include "flow.hpp"
#include "../dissector/parsed_packet.hpp"

// ── Events emitted by FlowEngine ─────────────────────────────────────────────
enum class FlowEvent { NEW, UPDATED, CLOSED, EXPIRED };

using FlowEventCallback = std::function<void(FlowEvent, std::shared_ptr<Flow>)>;

// ── FlowEngine ────────────────────────────────────────────────────────────────
// Subscribes to ParsedPacketBus and maintains a sharded flow table.
// Emits FlowEvent callbacks for integration with Module 4 (Metrics Engine).
//
// Thread model:
//   - process() called from ParsedPacketBus consumer thread (hot path, must be fast)
//   - expiry_loop() runs in a background thread sweeping 1 shard per tick
//   - FlowEventCallback may be called from either thread — must be thread-safe

class FlowEngine {
public:
    struct Config {
        // Idle timeout per protocol/state — flow is EXPIRED if no packet seen for this long
        int64_t tcp_established_timeout_ns = 300LL * 1'000'000'000LL; // 5 min
        int64_t tcp_syn_timeout_ns         =  10LL * 1'000'000'000LL; // 10 sec
        int64_t tcp_fin_timeout_ns         =  30LL * 1'000'000'000LL; // 30 sec
        int64_t udp_timeout_ns             =  30LL * 1'000'000'000LL; // 30 sec
        int64_t icmp_timeout_ns            =  10LL * 1'000'000'000LL; // 10 sec

        // Expiry sweep: rotate through all 64 shards in this interval
        int    expiry_sweep_interval_ms = 1000; // 1 shard per ~15ms

        // Memory guard: refuse new flows beyond this count to prevent OOM
        size_t max_active_flows = 100'000;
    };

    FlowEngine();
    explicit FlowEngine(const Config& cfg);
    ~FlowEngine();

    void set_event_callback(FlowEventCallback cb) { callback_ = std::move(cb); }

    void start();
    void stop();
    void reset();  // stop + clear table + restart

    // ── Hot path ─────────────────────────────────────────────────────────────
    // Called for every ParsedPacket from Module 2 via ParsedPacketBus.
    // noexcept: must never throw in the hot path.
    void process(const ParsedPacket& pkt) noexcept;

    size_t active_flows() const { return table_.total_active_flows(); }

    // Snapshot all active flows for API listing (copies shared_ptrs, not flow data)
    std::vector<std::shared_ptr<Flow>> snapshot_flows() const {
        return table_.snapshot();
    }

    // Find a single flow by ID — O(N) scan, API use only
    std::shared_ptr<Flow> find_flow_by_id(uint64_t id) const {
        return table_.find_by_id(id);
    }

private:
    Config            config_;
    FlowTable         table_;
    FlowEventCallback callback_;
    std::atomic<bool> running_{false};
    std::thread       expiry_thread_;
    std::atomic<uint64_t> next_flow_id_{1};

    // ── Flow lifecycle ────────────────────────────────────────────────────────
    std::shared_ptr<Flow> create_flow(const FlowKey& key, const ParsedPacket& pkt);
    void update_flow(Flow& f, const ParsedPacket& pkt, const FlowKey& key);

    // ── Per-protocol updaters (called with flow.mtx_ held) ───────────────────
    void update_tcp (Flow& f, const TcpFields&  tcp,  bool is_fwd, int64_t ts_ns);
    void update_dns (Flow& f, const DnsFields&  dns,  int64_t ts_ns);
    void update_http(Flow& f, const HttpFields& http);
    void update_tls (Flow& f, const TlsFields&  tls);

    // ── Helpers ───────────────────────────────────────────────────────────────
    void        set_expiry(Flow& f) noexcept;
    AppProtocol infer_app_protocol(const ParsedPacket& pkt) noexcept;

    // ── Background expiry loop ────────────────────────────────────────────────
    void expiry_loop();

    static bool is_forward(const ParsedPacket& pkt, const FlowKey& key) noexcept;
    static int64_t now_ns() noexcept;
};
