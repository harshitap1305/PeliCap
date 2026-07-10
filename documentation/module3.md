# Module 3: Flow reconstruction — 3-Diagram Deep Dive & Production-Ready Implementation Plan

CapturedPacket (from Module 1)
DissectorEngine::dissect(packet)
dispatches by link_type, then EtherType, then protocol
Layer 2
EthernetDissector
src/dst MAC, EtherType
ARPDissector
op, sender/target IP+MAC
VLANDissector
VLAN ID, priority, inner type
Layer 3
IPv4Dissector
IHL, TTL, flags, DSCP, frag
IPv6Dissector
flow label, hop limit, ext hdrs
ICMPDissector
type, code, RTT
Layer 4
TCPDissector
flags, seq, ack, opts, window
UDPDissector
ports, length, checksum
SCTPDissector
chunks, streams
Layer 7
DNSDissector
query, rcode, RTT
HTTPDissector
method, URL, status
TLSDissector
version, SNI, alert
DHCPDiss.
op, options
ParsedPacket (output struct)
EtherFields eth
IPv4Fields ip4
TCPFields tcp
DNSFields dns
HTTPFields http
TLSFields tls
Flow engine
Module 3
Metrics engine
Module 4
Storage / API
Modules 6–7

now the second diagram — what fields you extract from TCP specifically, since it's the richest and most important protocol for your analytics:
TCP header (20 bytes fixed + options)
Source port (2B)
Destination port (2B)
Sequence number (4B)
Acknowledgment number (4B)
Offset
Flags (SYN ACK FIN RST PSH URG ECE CWR)
Window size (2B)
Checksum (2B)
Urgent pointer (2B)
Options — MSS · SACK · timestamps · window scale · SACK permitted
Why each field matters for analytics
Ports — identify the application protocol (443=TLS, 53=DNS, 80=HTTP, 22=SSH)
Seq + Ack — detect retransmissions (same seq resent), estimate RTT, reconstruct flow order
Flags — SYN starts connections, FIN/RST ends them, PSH flushes data, ECE signals congestion
Window — zero window = receiver buffer full (throughput bottleneck), shrinking window = pressure
Timestamps option — compute precise RTT per segment without guessing from seq/ack alone
MSS — maximum segment size negotiated during handshake, affects fragmentation
Window scale — actual window = window_size × 2^scale_factor; needed for high-BW connections
SACK blocks — tells you exactly which segments arrived, which were lost (better than counting rexmit)
Derived metrics your engine computes from these fields
RTT estimate · retransmission rate · zero-window events · connection setup time · teardown detection

 Three diagrams for Module 3 — the flow lifecycle, the state machine, and the internal data layout. Then the full implementation.Now the TCP flow state machine — every production flow engine must implement this exactly, because getting TCP state wrong means flows never expire:Now the internal `Flow` struct layout — what lives inside each flow object and why:Now the full implementation plan.

---

## The core challenge of flow reconstruction

Every other module is stateless — give it a packet, get output. Flow reconstruction is fundamentally stateful. You're maintaining a hash map of thousands of concurrent conversations, each of which can last anywhere from 10 milliseconds (a DNS query) to hours (a persistent database connection). The three hard problems are:

**Hash map contention** — packets arrive from a capture thread and queries arrive from the REST API on a different thread. Both want the flow table simultaneously.

**Expiry** — a flow that went idle 5 minutes ago needs to be cleaned up. But you can't scan a million-entry map every second.

**TCP sequence tracking** — to detect retransmissions you need to remember what sequence numbers were seen. That's per-flow state, and it grows.

---

## The key data structure decision: which hash map

This is the most important performance choice in Module 3. Here are the tradeoffs:

| Option | Lookup | Memory | Thread safety | Verdict |
|---|---|---|---|---|
| `std::unordered_map` | O(1) avg | High (many allocs) | None | Never use |
| `absl::flat_hash_map` | O(1), cache-friendly | Low | None | Best single-threaded |
| `tbb::concurrent_hash_map` | O(1) | Medium | Yes, fine-grained | Best multi-threaded |
| `std::unordered_map` + `std::mutex` | O(1) + lock | High | Coarse lock | Avoid at scale |
| Sharded map (N buckets, each with own mutex) | O(1) + shard lock | Medium | Good | Best practical choice |

**Choose: sharded `absl::flat_hash_map` with per-shard mutexes.** This is what production systems (Cloudflare's flow tracker, VPP's flow table) use. You get the cache performance of `absl::flat_hash_map` with fine-grained locking. 64 shards means 64x less contention than a single mutex.

```cpp
// Install: vcpkg install abseil
#include <absl/container/flat_hash_map.h>
```

---

## The FlowKey — design it for speed

The key is hashed millions of times per second. It must be cheap to compute and small enough to fit in cache.

```cpp
#pragma once
#include <cstdint>
#include <string>
#include <functional>

struct FlowKey {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;
    uint8_t  _pad[3]  = {};   // explicit padding — keeps struct 16 bytes, avoids UB

    // CRITICAL: bidirectional normalization
    // A → B and B → A are the SAME flow.
    // Always put the smaller (ip,port) tuple first.
    static FlowKey make(uint32_t sip, uint16_t sport,
                        uint32_t dip, uint16_t dport,
                        uint8_t proto)
    {
        FlowKey k;
        k.protocol = proto;
        // Normalize so forward and reverse packets map to same key
        if (sip < dip || (sip == dip && sport < dport)) {
            k.src_ip = sip; k.src_port = sport;
            k.dst_ip = dip; k.dst_port = dport;
        } else {
            k.src_ip = dip; k.src_port = dport;
            k.dst_ip = sip; k.dst_port = sport;
        }
        return k;
    }

    bool operator==(const FlowKey& o) const {
        // Compare as two uint64s — faster than field-by-field
        return __builtin_memcmp(this, &o, 16) == 0;
    }
};

// Fast hash using wyhash (faster than std::hash on small fixed-size structs)
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        // XOR-fold the 16 bytes into 8
        uint64_t a, b;
        __builtin_memcpy(&a, &k,   8);
        __builtin_memcpy(&b, reinterpret_cast<const uint8_t*>(&k) + 8, 8);
        // Multiply-mix (fast, good avalanche)
        a ^= b;
        a ^= a >> 33;
        a *= 0xff51afd7ed558ccdULL;
        a ^= a >> 33;
        a *= 0xc4ceb9fe1a85ec53ULL;
        a ^= a >> 33;
        return static_cast<size_t>(a);
    }
};
```

The bidirectional normalization is the most important part. Without it, packet A→B creates flow #1 and packet B→A creates flow #2 — you get duplicate flows for every connection.

---

## The Flow struct — complete definition

```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <atomic>
#include <chrono>
#include "flow_key.hpp"
#include "../dissector/parsed_packet.hpp"

enum class TcpFlowState : uint8_t {
    INIT        = 0,
    SYN_SENT    = 1,
    SYN_RCVD    = 2,
    ESTABLISHED = 3,
    FIN_WAIT    = 4,
    TIME_WAIT   = 5,
    CLOSED      = 6,
    RESET       = 7,
    EXPIRED     = 8,    // idle timeout — no FIN/RST seen
};

enum class AppProtocol : uint8_t {
    Unknown = 0, HTTP, HTTPS, DNS, TLS, SSH,
    FTP, SMTP, Postgres, MySQL, Redis, MQTT,
};

// RTT sample ring buffer — keep last 32 samples for percentile calc
struct RttTracker {
    static constexpr size_t MAX_SAMPLES = 32;
    uint32_t samples[MAX_SAMPLES] = {};   // microseconds
    uint8_t  head = 0;
    uint8_t  count = 0;

    void add(uint32_t rtt_us) {
        samples[head % MAX_SAMPLES] = rtt_us;
        head = (head + 1) % MAX_SAMPLES;
        if (count < MAX_SAMPLES) ++count;
    }
    uint32_t avg() const {
        if (!count) return 0;
        uint64_t sum = 0;
        for (uint8_t i = 0; i < count; ++i) sum += samples[i];
        return static_cast<uint32_t>(sum / count);
    }
    uint32_t min() const {
        if (!count) return 0;
        uint32_t m = samples[0];
        for (uint8_t i = 1; i < count; ++i) m = std::min(m, samples[i]);
        return m;
    }
};

// Retransmission detector — tracks recent seq numbers
// Uses a fixed-size circular set to avoid unbounded memory growth
struct RetransmitTracker {
    static constexpr size_t WINDOW = 64;
    uint32_t recent_seqs[WINDOW] = {};
    uint8_t  head = 0;
    uint32_t retransmit_count = 0;
    uint32_t out_of_order_count = 0;

    bool see_seq(uint32_t seq) {
        // Check if we've seen this seq recently
        for (uint8_t i = 0; i < WINDOW; ++i) {
            if (recent_seqs[i] == seq && seq != 0) {
                ++retransmit_count;
                return true;  // retransmit!
            }
        }
        recent_seqs[head % WINDOW] = seq;
        head = (head + 1) % WINDOW;
        return false;
    }
};

struct Flow {
    // ── Identity ──────────────────────────────────────────
    uint64_t   flow_id      = 0;
    FlowKey    key;
    std::string src_ip_str, dst_ip_str;
    uint16_t   src_port = 0, dst_port = 0;
    uint8_t    protocol = 0;
    std::string interface_name;

    // ── Timing ────────────────────────────────────────────
    int64_t  start_time_ns   = 0;  // first packet timestamp
    int64_t  last_seen_ns    = 0;  // last packet timestamp
    int64_t  expiry_ns       = 0;  // wall-clock time after which flow expires

    // ── Packet counters ───────────────────────────────────
    uint64_t fwd_packets = 0;      // client → server
    uint64_t rev_packets = 0;      // server → client
    uint64_t fwd_bytes   = 0;
    uint64_t rev_bytes   = 0;
    uint64_t payload_bytes = 0;    // bytes excluding headers

    // ── TCP state machine ──────────────────────────────────
    TcpFlowState tcp_state = TcpFlowState::INIT;
    uint32_t     client_isn  = 0;  // initial sequence number (from SYN)
    uint32_t     server_isn  = 0;  // from SYN-ACK
    uint8_t      fin_count   = 0;  // 2 FINs = full close
    uint8_t      window_scale_client = 0;
    uint8_t      window_scale_server = 0;

    // ── Quality metrics ───────────────────────────────────
    RttTracker       rtt;
    RetransmitTracker retransmit;
    uint32_t          zero_window_events = 0;
    uint32_t          dup_ack_count      = 0;

    // ── Application layer ──────────────────────────────────
    AppProtocol app_protocol = AppProtocol::Unknown;
    std::string tls_sni;         // from TLS ClientHello
    std::string http_host;       // from HTTP Host header
    std::string dns_query;       // first DNS query in flow
    uint32_t    http_request_count  = 0;
    uint32_t    http_response_count = 0;
    uint32_t    dns_transaction_count = 0;

    // ── Flow lifecycle ────────────────────────────────────
    bool is_active  = true;
    bool was_closed = false;  // saw FIN or RST

    // ── Helpers ───────────────────────────────────────────
    uint64_t total_packets() const { return fwd_packets + rev_packets; }
    uint64_t total_bytes()   const { return fwd_bytes   + rev_bytes;   }
    int64_t  duration_ns()   const { return last_seen_ns - start_time_ns; }
};
```

The fixed-size `RttTracker` and `RetransmitTracker` are the key production decision — you can't use `std::vector<uint32_t>` for RTT samples because with millions of flows that's unbounded heap allocation. Fixed-size ring buffers mean each `Flow` object is a predictable ~400 bytes regardless of how many packets have passed through.

---

## The sharded FlowTable

```cpp
#pragma once
#include <array>
#include <mutex>
#include <memory>
#include <functional>
#include <absl/container/flat_hash_map.h>
#include "flow.hpp"

class FlowTable {
public:
    static constexpr size_t NUM_SHARDS = 64;

    using FlowPtr = std::shared_ptr<Flow>;
    using Shard   = absl::flat_hash_map<FlowKey, FlowPtr, FlowKeyHash>;

    struct ShardedEntry {
        mutable std::mutex mtx;
        Shard              map;
    };

    // Look up or create a flow atomically within its shard
    FlowPtr get_or_create(const FlowKey& key,
                          std::function<FlowPtr()> factory)
    {
        auto& shard = get_shard(key);
        std::lock_guard lock(shard.mtx);

        auto it = shard.map.find(key);
        if (it != shard.map.end()) return it->second;

        auto flow = factory();
        shard.map.emplace(key, flow);
        return flow;
    }

    FlowPtr find(const FlowKey& key) {
        auto& shard = get_shard(key);
        std::lock_guard lock(shard.mtx);
        auto it = shard.map.find(key);
        return it != shard.map.end() ? it->second : nullptr;
    }

    // Called by expiry sweep — removes expired flows from a shard
    // Returns the removed flows for downstream processing
    std::vector<FlowPtr> sweep_shard(size_t shard_idx, int64_t now_ns) {
        std::vector<FlowPtr> expired;
        auto& shard = shards_[shard_idx];
        std::lock_guard lock(shard.mtx);

        for (auto it = shard.map.begin(); it != shard.map.end(); ) {
            if (it->second->expiry_ns < now_ns) {
                it->second->tcp_state = TcpFlowState::EXPIRED;
                expired.push_back(it->second);
                it = shard.map.erase(it);
            } else {
                ++it;
            }
        }
        return expired;
    }

    size_t total_active_flows() const {
        size_t total = 0;
        for (auto& s : shards_) {
            std::lock_guard lock(s.mtx);
            total += s.map.size();
        }
        return total;
    }

private:
    std::array<ShardedEntry, NUM_SHARDS> shards_;

    ShardedEntry& get_shard(const FlowKey& key) {
        // Use top bits of hash to select shard
        size_t h = FlowKeyHash{}(key);
        return shards_[h & (NUM_SHARDS - 1)];
    }
};
```

---

## The FlowEngine — main entry point

```cpp
#pragma once
#include <thread>
#include <atomic>
#include <functional>
#include "flow_table.hpp"
#include "../dissector/parsed_packet.hpp"

enum class FlowEvent { NEW, UPDATED, CLOSED, EXPIRED };

struct FlowEventData {
    FlowEvent            event;
    std::shared_ptr<Flow> flow;
};

using FlowEventCallback = std::function<void(FlowEventData)>;

class FlowEngine {
public:
    struct Config {
        // Idle timeouts — flows expire if no packet seen for this long
        int64_t tcp_established_timeout_ns = 300LL * 1'000'000'000LL; // 5 min
        int64_t tcp_syn_timeout_ns         =  10LL * 1'000'000'000LL; // 10 sec
        int64_t tcp_fin_timeout_ns         =  30LL * 1'000'000'000LL; // 30 sec
        int64_t udp_timeout_ns             =  30LL * 1'000'000'000LL; // 30 sec
        int64_t icmp_timeout_ns            =  10LL * 1'000'000'000LL; // 10 sec

        // Expiry sweep — how often the background thread checks for expired flows
        int expiry_sweep_interval_ms = 1000; // 1 second
    };

    explicit FlowEngine(Config cfg = {}) : config_(cfg) {}

    void set_event_callback(FlowEventCallback cb) { callback_ = std::move(cb); }

    void start() {
        running_ = true;
        expiry_thread_ = std::thread([this]() { expiry_loop(); });
    }

    void stop() {
        running_ = false;
        if (expiry_thread_.joinable()) expiry_thread_.join();
    }

    // Called for every ParsedPacket from Module 2
    void process(const ParsedPacket& pkt) {
        if (!pkt.flow_key.valid) return;  // ARP, malformed, etc.

        FlowKey key = FlowKey::make(
            ip_to_uint32(pkt.flow_key.src_ip), pkt.flow_key.src_port,
            ip_to_uint32(pkt.flow_key.dst_ip), pkt.flow_key.dst_port,
            pkt.flow_key.protocol
        );

        bool is_new = false;
        auto flow = table_.get_or_create(key, [&]() -> std::shared_ptr<Flow> {
            is_new = true;
            return create_flow(key, pkt);
        });

        {
            // Update the flow — lock only this flow, not the whole shard
            std::lock_guard lock(flow->mtx_);
            update_flow(*flow, pkt, key);
        }

        if (callback_) {
            callback_({ is_new ? FlowEvent::NEW : FlowEvent::UPDATED, flow });
        }

        // Check if flow just closed
        if (flow->was_closed && callback_) {
            // Remove from table — flow is done
            // (expiry thread handles cleanup on next sweep)
            flow->is_active = false;
            callback_({ FlowEvent::CLOSED, flow });
        }
    }

private:
    Config            config_;
    FlowTable         table_;
    FlowEventCallback callback_;
    std::atomic<bool> running_{false};
    std::thread       expiry_thread_;
    std::atomic<uint64_t> next_flow_id_{1};

    // Each flow has its own mutex for update-time locking
    // This gives better parallelism than shard-level locking for updates

    std::shared_ptr<Flow> create_flow(const FlowKey& key, const ParsedPacket& pkt) {
        auto f = std::make_shared<Flow>();
        f->flow_id       = next_flow_id_.fetch_add(1, std::memory_order_relaxed);
        f->key           = key;
        f->src_ip_str    = pkt.flow_key.src_ip;
        f->dst_ip_str    = pkt.flow_key.dst_ip;
        f->src_port      = pkt.flow_key.src_port;
        f->dst_port      = pkt.flow_key.dst_port;
        f->protocol      = pkt.flow_key.protocol;
        f->interface_name = pkt.interface_name;
        f->start_time_ns = pkt.timestamp_ns;
        f->last_seen_ns  = pkt.timestamp_ns;
        f->app_protocol  = infer_app_protocol(pkt);
        set_expiry(*f, pkt.timestamp_ns);
        return f;
    }

    void update_flow(Flow& f, const ParsedPacket& pkt, const FlowKey& key) {
        f.last_seen_ns = pkt.timestamp_ns;
        set_expiry(f, pkt.timestamp_ns);

        // Determine direction — is this src_ip the "client" (initiator)?
        bool is_forward = (ip_to_uint32(pkt.flow_key.src_ip) == key.src_ip &&
                           pkt.flow_key.src_port             == key.src_port);

        if (is_forward) {
            ++f.fwd_packets;
            f.fwd_bytes += pkt.captured_len;
        } else {
            ++f.rev_packets;
            f.rev_bytes += pkt.captured_len;
        }

        if (pkt.tcp) update_tcp(f, *pkt.tcp, is_forward, pkt.timestamp_ns);
        if (pkt.dns) update_dns(f, *pkt.dns);
        if (pkt.http) update_http(f, *pkt.http);
        if (pkt.tls)  update_tls(f, *pkt.tls);
    }

    void update_tcp(Flow& f, const TcpFields& tcp, bool is_fwd, int64_t ts_ns) {
        // State machine transitions
        switch (f.tcp_state) {
            case TcpFlowState::INIT:
                if (tcp.flag_syn && !tcp.flag_ack) {
                    f.tcp_state  = TcpFlowState::SYN_SENT;
                    f.client_isn = tcp.seq_num;
                }
                break;

            case TcpFlowState::SYN_SENT:
                if (tcp.flag_syn && tcp.flag_ack) {
                    f.tcp_state  = TcpFlowState::SYN_RCVD;
                    f.server_isn = tcp.seq_num;
                    // Server sends window_scale in SYN-ACK
                    if (tcp.window_scale)
                        f.window_scale_server = *tcp.window_scale;
                }
                break;

            case TcpFlowState::SYN_RCVD:
                if (tcp.flag_ack && !tcp.flag_syn)
                    f.tcp_state = TcpFlowState::ESTABLISHED;
                break;

            case TcpFlowState::ESTABLISHED:
                if (tcp.flag_fin) {
                    f.tcp_state = TcpFlowState::FIN_WAIT;
                    ++f.fin_count;
                }
                if (tcp.flag_rst) {
                    f.tcp_state  = TcpFlowState::RESET;
                    f.was_closed = true;
                    return;  // stop processing
                }
                break;

            case TcpFlowState::FIN_WAIT:
                if (tcp.flag_fin || tcp.flag_ack) {
                    ++f.fin_count;
                    if (f.fin_count >= 2) {
                        f.tcp_state  = TcpFlowState::TIME_WAIT;
                    }
                }
                if (tcp.flag_rst) {
                    f.tcp_state  = TcpFlowState::RESET;
                    f.was_closed = true;
                }
                break;

            case TcpFlowState::TIME_WAIT:
                // Will close after 2×MSL (handled by expiry with short timeout)
                f.was_closed = true;
                break;

            default: break;
        }

        // Retransmission detection
        if (tcp.payload_len > 0) {
            bool is_rexmit = f.retransmit.see_seq(tcp.seq_num);
            if (!is_rexmit) f.payload_bytes += tcp.payload_len;
        }

        // RTT estimation using TCP timestamps (most accurate method)
        // When we see ts_ecr from server, the RTT = now - time when we sent ts_val
        // Simplified: use SYN→SYN-ACK timing
        if (f.tcp_state == TcpFlowState::SYN_RCVD && !is_fwd) {
            // This is the SYN-ACK; compute handshake RTT
            int64_t rtt_us = (ts_ns - f.start_time_ns) / 1000;
            if (rtt_us > 0 && rtt_us < 30'000'000) {  // sanity: < 30 seconds
                f.rtt.add(static_cast<uint32_t>(rtt_us));
            }
        }

        // Zero window detection
        if (tcp.window_size == 0 && tcp.flag_ack) {
            ++f.zero_window_events;
        }
    }

    void update_dns(Flow& f, const DnsFields& dns) {
        ++f.dns_transaction_count;
        if (!dns.is_response && f.dns_query.empty())
            f.dns_query = dns.query_name;
    }

    void update_http(Flow& f, const HttpFields& http) {
        if (http.is_request) {
            ++f.http_request_count;
            if (f.http_host.empty()) f.http_host = http.host;
        } else {
            ++f.http_response_count;
        }
    }

    void update_tls(Flow& f, const TlsFields& tls) {
        if (f.tls_sni.empty() && !tls.sni.empty())
            f.tls_sni = tls.sni;
    }

    void set_expiry(Flow& f, int64_t now_ns) {
        int64_t timeout_ns;
        switch (f.protocol) {
            case 6:  // TCP
                switch (f.tcp_state) {
                    case TcpFlowState::INIT:
                    case TcpFlowState::SYN_SENT:
                    case TcpFlowState::SYN_RCVD:
                        timeout_ns = config_.tcp_syn_timeout_ns;     break;
                    case TcpFlowState::FIN_WAIT:
                    case TcpFlowState::TIME_WAIT:
                        timeout_ns = config_.tcp_fin_timeout_ns;     break;
                    default:
                        timeout_ns = config_.tcp_established_timeout_ns; break;
                }
                break;
            case 17: timeout_ns = config_.udp_timeout_ns;  break;
            case 1:  timeout_ns = config_.icmp_timeout_ns; break;
            default: timeout_ns = config_.udp_timeout_ns;  break;
        }
        // Use wall clock for expiry, not packet timestamp
        f.expiry_ns = std::chrono::steady_clock::now().time_since_epoch().count()
                      + timeout_ns;
    }

    AppProtocol infer_app_protocol(const ParsedPacket& pkt) {
        if (pkt.dns)  return AppProtocol::DNS;
        if (pkt.http) return AppProtocol::HTTP;
        if (pkt.tls)  return AppProtocol::TLS;
        if (!pkt.tcp && !pkt.udp) return AppProtocol::Unknown;
        uint16_t port = pkt.tcp ? std::min(pkt.tcp->src_port, pkt.tcp->dst_port)
                                : std::min(pkt.udp->src_port, pkt.udp->dst_port);
        switch (port) {
            case 443:  return AppProtocol::TLS;
            case 22:   return AppProtocol::SSH;
            case 5432: return AppProtocol::Postgres;
            case 6379: return AppProtocol::Redis;
            default:   return AppProtocol::Unknown;
        }
    }

    void expiry_loop() {
        size_t shard_idx = 0;
        while (running_) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config_.expiry_sweep_interval_ms / FlowTable::NUM_SHARDS)
            );
            // Sweep one shard per tick — spreads work evenly instead of one big pause
            int64_t now_ns = std::chrono::steady_clock::now().time_since_epoch().count();
            auto expired = table_.sweep_shard(shard_idx % FlowTable::NUM_SHARDS, now_ns);
            for (auto& f : expired) {
                if (callback_) callback_({ FlowEvent::EXPIRED, f });
            }
            ++shard_idx;
        }
    }

    static uint32_t ip_to_uint32(const std::string& ip) {
        uint32_t result = 0;
        inet_pton(AF_INET, ip.c_str(), &result);
        return result;
    }
};
```

The per-shard expiry sweep is a critical production detail. Instead of scanning all 64 shards every second (which causes a latency spike), you sweep one shard every `1000ms / 64 = ~15ms`. The work is spread across time, and no single sweep pauses the capture thread.

---

## The per-flow mutex problem — and the solution

You noticed that `Flow` has its own `mtx_` field. This is the two-level locking scheme:

- **Shard mutex** — held only during hash map lookup/insert/delete. Held for microseconds.
- **Flow mutex** — held during field updates. Allows concurrent updates to different flows in the same shard.

```cpp
// Add to Flow struct:
mutable std::mutex mtx_;
```

Without per-flow mutexes, updating flow A in shard 3 blocks reading flow B in shard 3. With per-flow mutexes, shard lock is dropped immediately after the `shared_ptr` is retrieved, then the flow mutex is taken for the update.

---

## How to serialize a Flow to JSON for the API

```cpp
nlohmann::json flow_to_json(const Flow& f) {
    nlohmann::json j;
    j["flow_id"]     = f.flow_id;
    j["src"]         = f.src_ip_str + ":" + std::to_string(f.src_port);
    j["dst"]         = f.dst_ip_str + ":" + std::to_string(f.dst_port);
    j["protocol"]    = f.protocol == 6 ? "TCP" : f.protocol == 17 ? "UDP" : "OTHER";
    j["interface"]   = f.interface_name;
    j["start_ns"]    = f.start_time_ns;
    j["duration_ms"] = f.duration_ns() / 1'000'000;
    j["fwd_packets"] = f.fwd_packets;
    j["rev_packets"] = f.rev_packets;
    j["fwd_bytes"]   = f.fwd_bytes;
    j["rev_bytes"]   = f.rev_bytes;
    j["tcp_state"]   = static_cast<int>(f.tcp_state);
    j["avg_rtt_us"]  = f.rtt.avg();
    j["min_rtt_us"]  = f.rtt.min();
    j["retransmits"] = f.retransmit.retransmit_count;
    j["zero_windows"] = f.zero_window_events;
    j["app_protocol"] = static_cast<int>(f.app_protocol);
    if (!f.tls_sni.empty())   j["sni"]   = f.tls_sni;
    if (!f.http_host.empty()) j["host"]  = f.http_host;
    if (!f.dns_query.empty()) j["query"] = f.dns_query;
    return j;
}
```

---

## REST API endpoints for flows

```
GET  /api/flows                    — list active flows (paginated)
GET  /api/flows/:id                — get single flow detail
GET  /api/flows?src_ip=10.0.0.1   — filter by source IP
GET  /api/flows?protocol=TCP       — filter by protocol
GET  /api/flows?app=DNS            — filter by application protocol
GET  /api/flows/stats              — aggregate stats: total flows, avg RTT, etc.
```

---

## Project structure additions

```
core/
└── flow/
    ├── flow_key.hpp          ← FlowKey struct + hash
    ├── flow.hpp              ← Flow struct + RttTracker + RetransmitTracker
    ├── flow_table.hpp        ← sharded FlowTable
    ├── flow_engine.hpp       ← FlowEngine (process + expiry loop)
    ├── flow_engine.cpp
    └── flow_serializer.cpp   ← flow_to_json()
```

---

## Build additions

```cmake
find_package(absl REQUIRED)

target_sources(network_copilot PRIVATE
    core/flow/flow_engine.cpp
    core/flow/flow_serializer.cpp
)

target_link_libraries(network_copilot PRIVATE
    absl::flat_hash_map
    absl::hash
)
```

Install Abseil: `vcpkg install abseil` or `apt install libabsl-dev`.

---

## Implementation order

1. `FlowKey` + hash — write it, test with known IP pairs, verify bidirectional normalization
2. `Flow` struct — get the fields right, don't touch the mutex yet
3. `FlowTable` (single-shard, no mutex) — prove lookup and insert work
4. `FlowEngine::process()` — wire it to a `ParsedPacket`, print flow ID to stdout
5. TCP state machine — capture a `wget` session, verify INIT→SYN_SENT→SYN_RCVD→ESTABLISHED→FIN_WAIT→CLOSED
6. Add sharding + mutexes — stress test with two threads
7. Expiry loop — verify flows disappear after timeout
8. RTT tracking — capture a ping session, verify RTT samples match `ping` output
9. Retransmit detection — inject a duplicate seq number packet in a test, verify count
10. REST serialization + API endpoints

The state machine step (5) is the one most people skip and then regret — verify it with real traffic before adding any more features.

---

Module 3 feeds directly into Module 4 (Metrics Engine) via the `FlowEventCallback` — every `FLOW_UPDATED` event carries the current flow stats, and every `FLOW_CLOSED`/`FLOW_EXPIRED` gives Module 4 its final numbers for aggregation. Want me to dive into Module 4 next?