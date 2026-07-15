#include "flow_engine.hpp"
#include <cstring>

// ── Constructor / Destructor ─────────────────────────────────────────────────

FlowEngine::FlowEngine() : config_() {}
FlowEngine::FlowEngine(const Config& cfg) : config_(cfg) {}

FlowEngine::~FlowEngine() { stop(); }

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void FlowEngine::start() {
    if (running_.exchange(true)) return;
    expiry_thread_ = std::thread([this]() { expiry_loop(); });
}

void FlowEngine::stop() {
    running_ = false;
    if (expiry_thread_.joinable()) expiry_thread_.join();
}

void FlowEngine::reset() {
    stop();
    // Flush all active flows before clearing
    auto snapshot = table_.snapshot();
    for (auto& f : snapshot) {
        if (f && f->is_active) {
            f->tcp_state = TcpFlowState::CLOSED;
            f->is_active = false;
            if (callback_) callback_(FlowEvent::CLOSED, f);
        }
    }
    table_.clear();
    next_flow_id_ = 1;
    start();
}

// ── Hot path ──────────────────────────────────────────────────────────────────

void FlowEngine::process(const ParsedPacket& pkt) noexcept {
    // Build FlowKey — returns nullopt for ARP and packets without an IP layer
    auto opt_key = FlowKey::from_packet(pkt);
    if (!opt_key) return;
    const FlowKey& key = *opt_key;

    bool is_new = false;
    auto flow = table_.get_or_create(key,
        [&]() -> std::shared_ptr<Flow> {
            is_new = true;
            return create_flow(key, pkt);
        },
        config_.max_active_flows
    );

    if (!flow) return;  // table full, dropped

    {
        std::lock_guard<std::mutex> lk(flow->mtx_);
        update_flow(*flow, pkt, key);
    }

    if (callback_) {
        bool closed = flow->was_closed;
        callback_(is_new ? FlowEvent::NEW : FlowEvent::UPDATED, flow);

        // Emit CLOSED immediately so the API history captures short-lived flows
        if (closed && flow->is_active) {
            flow->is_active = false;
            table_.remove(key);
            callback_(FlowEvent::CLOSED, flow);
        }
    }
}

// ── Flow creation ──────────────────────────────────────────────────────────────

std::shared_ptr<Flow> FlowEngine::create_flow(const FlowKey& key,
                                               const ParsedPacket& pkt) {
    auto f = std::make_shared<Flow>();
    f->flow_id        = next_flow_id_.fetch_add(1, std::memory_order_relaxed);
    f->key            = key;
    f->protocol       = key.protocol;
    f->is_ipv6        = key.is_ipv6;
    f->interface_name = pkt.interface_name;
    f->session_id     = pkt.session_id;
    f->start_time_ns  = pkt.timestamp_ns;
    f->last_seen_ns   = pkt.timestamp_ns;
    f->app_protocol   = infer_app_protocol(pkt);

    // Fill human-readable address strings
    if (pkt.ip4) {
        // Determine which side is "src" in the normalised key
        uint32_t pkt_src = pkt.ip4->src_ip;
        uint8_t  tmp[4];
        std::memcpy(tmp, key.src_addr, 4);
        uint32_t key_src;
        std::memcpy(&key_src, tmp, 4);

        if (pkt_src == key_src) {
            f->src_ip_str = pkt.ip4->src_ip_str;
            f->dst_ip_str = pkt.ip4->dst_ip_str;
        } else {
            f->src_ip_str = pkt.ip4->dst_ip_str;
            f->dst_ip_str = pkt.ip4->src_ip_str;
        }
    } else if (pkt.ip6) {
        if (pkt.ip6->src_ip_raw == *reinterpret_cast<const std::array<uint8_t,16>*>(key.src_addr)) {
            f->src_ip_str = pkt.ip6->src_ip_str;
            f->dst_ip_str = pkt.ip6->dst_ip_str;
        } else {
            f->src_ip_str = pkt.ip6->dst_ip_str;
            f->dst_ip_str = pkt.ip6->src_ip_str;
        }
    }

    f->src_port = key.src_port;
    f->dst_port = key.dst_port;

    set_expiry(*f);
    return f;
}

// ── Flow update ───────────────────────────────────────────────────────────────

void FlowEngine::update_flow(Flow& f, const ParsedPacket& pkt, const FlowKey& key) {
    f.last_seen_ns = pkt.timestamp_ns;
    set_expiry(f);

    bool fwd = is_forward(pkt, key);
    uint32_t pkt_bytes = pkt.captured_len;

    if (fwd) { ++f.fwd_packets; f.fwd_bytes += pkt_bytes; }
    else      { ++f.rev_packets; f.rev_bytes += pkt_bytes; }

    if (pkt.tcp)  update_tcp(f, *pkt.tcp,  fwd, pkt.timestamp_ns);
    if (pkt.dns)  update_dns(f, *pkt.dns,  pkt.timestamp_ns);
    if (pkt.http) update_http(f, *pkt.http, pkt.timestamp_ns);
    if (pkt.tls)  update_tls(f, *pkt.tls);
}

// ── TCP state machine ─────────────────────────────────────────────────────────

void FlowEngine::update_tcp(Flow& f, const TcpFields& tcp, bool is_fwd, int64_t ts_ns) {

    // ── State machine ────────────────────────────────────────────────────────
    switch (f.tcp_state) {

        case TcpFlowState::INIT:
            if (tcp.flag_syn && !tcp.flag_ack) {
                f.tcp_state   = TcpFlowState::SYN_SENT;
                f.client_isn  = tcp.seq_num;
                f.syn_time_ns = ts_ns;
                if (tcp.window_scale)
                    f.window_scale_client = *tcp.window_scale;
            } else if (tcp.flag_ack && !tcp.flag_syn) {
                // Capture started mid-connection — no SYN seen
                f.tcp_state = TcpFlowState::MID_STREAM;
            }
            break;

        case TcpFlowState::SYN_SENT:
            if (tcp.flag_syn && tcp.flag_ack) {
                f.tcp_state   = TcpFlowState::SYN_RCVD;
                f.server_isn  = tcp.seq_num;
                // Handshake RTT = time from SYN to SYN-ACK (one-way propagation)
                int64_t rtt_us = (ts_ns - f.syn_time_ns) / 1000;
                if (rtt_us > 0) {
                    f.handshake_rtt_us = static_cast<uint32_t>(rtt_us);
                    f.rtt.add(f.handshake_rtt_us);
                }
                if (tcp.window_scale)
                    f.window_scale_server = *tcp.window_scale;
            } else if (tcp.flag_rst) {
                f.tcp_state  = TcpFlowState::RESET;
                f.was_closed = true;
            }
            break;

        case TcpFlowState::SYN_RCVD:
            if (tcp.flag_ack && !tcp.flag_syn && !tcp.flag_fin) {
                f.tcp_state = TcpFlowState::ESTABLISHED;
                // Connection setup time = SYN to final ACK (full 3-way)
                int64_t setup_us = (ts_ns - f.syn_time_ns) / 1000;
                if (setup_us > 0)
                    f.connection_setup_us = static_cast<uint32_t>(setup_us);
            }
            break;

        case TcpFlowState::ESTABLISHED:
        case TcpFlowState::MID_STREAM:
            if (tcp.flag_rst) {
                f.tcp_state  = TcpFlowState::RESET;
                f.was_closed = true;
                return;
            }
            if (tcp.flag_fin) {
                f.tcp_state = TcpFlowState::FIN_WAIT;
                ++f.fin_count;
            }
            break;

        case TcpFlowState::FIN_WAIT:
            if (tcp.flag_rst) {
                f.tcp_state  = TcpFlowState::RESET;
                f.was_closed = true;
                return;
            }
            if (tcp.flag_fin) {
                ++f.fin_count;
                if (f.fin_count >= 2)
                    f.tcp_state = TcpFlowState::TIME_WAIT;
            }
            if (tcp.flag_ack && f.fin_count >= 2)
                f.tcp_state = TcpFlowState::TIME_WAIT;
            break;

        case TcpFlowState::TIME_WAIT:
            f.tcp_state  = TcpFlowState::CLOSED;
            f.was_closed = true;
            break;

        default:
            break;
    }

    // ── RTT via TCP timestamps (most accurate — works after handshake) ────────
    if (tcp.ts_val && tcp.ts_ecr) {
        if (is_fwd) {
            // Record outgoing ts_val with send time
            f.ts_rtt.record(*tcp.ts_val, ts_ns);
        } else {
            // Server echoes our ts_val back as ts_ecr
            int64_t send_ns = f.ts_rtt.match_ecr(*tcp.ts_ecr);
            if (send_ns > 0) {
                int64_t rtt_us = (ts_ns - send_ns) / 1000;
                f.rtt.add(static_cast<uint32_t>(rtt_us));
            }
        }
    }

    // ── Retransmit detection ──────────────────────────────────────────────────
    f.retransmit.see_seq(tcp.seq_num, tcp.payload_len);
    if (tcp.payload_len > 0)
        f.payload_bytes += tcp.payload_len;

    // ── Zero-window detection ─────────────────────────────────────────────────
    if (tcp.window_size == 0 && tcp.flag_ack && tcp.payload_len == 0)
        ++f.zero_window_events;

    // ── Duplicate ACK detection ───────────────────────────────────────────────
    uint32_t& last_ack    = is_fwd ? f.last_ack_fwd    : f.last_ack_rev;
    uint8_t&  dup_streak  = is_fwd ? f.dup_ack_streak_fwd : f.dup_ack_streak_rev;
    if (tcp.flag_ack && tcp.payload_len == 0 && tcp.ack_num == last_ack && last_ack != 0) {
        ++dup_streak;
        if (dup_streak >= 3) {
            ++f.dup_ack_count;
            dup_streak = 0;  // reset streak, but keep counting dup-ACK events
        }
    } else {
        last_ack   = tcp.ack_num;
        dup_streak = 0;
    }
}

// ── DNS RTT ───────────────────────────────────────────────────────────────────

void FlowEngine::update_dns(Flow& f, const DnsFields& dns, int64_t ts_ns) {
    ++f.dns_transaction_count;
    if (!dns.is_response) {
        if (f.dns_query.empty())
            f.dns_query = dns.query_name;
        f.dns_rtt.record_query(dns.transaction_id, ts_ns);
    } else {
        int64_t send_ns = f.dns_rtt.match_response(dns.transaction_id);
        if (send_ns > 0) {
            int64_t rtt_us = (ts_ns - send_ns) / 1000;
            f.rtt.add(static_cast<uint32_t>(rtt_us));
        }
    }
}

// ── HTTP / TLS ────────────────────────────────────────────────────────────────

void FlowEngine::update_http(Flow& f, const HttpFields& http, int64_t ts_ns) {
    if (http.is_request) {
        ++f.http_request_count;
        if (f.http_host.empty() && !http.host.empty())
            f.http_host = http.host;
        // Record timestamp of first HTTP request for latency calculation
        if (f.http_request_first_seen_ns == 0)
            f.http_request_first_seen_ns = ts_ns;
    } else {
        ++f.http_response_count;
    }
}

void FlowEngine::update_tls(Flow& f, const TlsFields& tls) {
    if (f.tls_sni.empty() && !tls.sni.empty())
        f.tls_sni = tls.sni;
}

// ── Expiry helpers ────────────────────────────────────────────────────────────

void FlowEngine::set_expiry(Flow& f) noexcept {
    int64_t timeout_ns;
    if (f.protocol == 6) {  // TCP
        switch (f.tcp_state) {
            case TcpFlowState::INIT:
            case TcpFlowState::SYN_SENT:
            case TcpFlowState::SYN_RCVD:
                timeout_ns = config_.tcp_syn_timeout_ns; break;
            case TcpFlowState::FIN_WAIT:
            case TcpFlowState::TIME_WAIT:
            case TcpFlowState::CLOSED:
            case TcpFlowState::RESET:
                timeout_ns = config_.tcp_fin_timeout_ns; break;
            default:
                timeout_ns = config_.tcp_established_timeout_ns; break;
        }
    } else if (f.protocol == 17) {  // UDP
        timeout_ns = config_.udp_timeout_ns;
    } else {  // ICMP, ICMPv6, others
        timeout_ns = config_.icmp_timeout_ns;
    }
    // Use wall-clock (steady_clock), not packet timestamps, for expiry
    f.expiry_ns = now_ns() + timeout_ns;
}

AppProtocol FlowEngine::infer_app_protocol(const ParsedPacket& pkt) noexcept {
    if (pkt.dns)  return AppProtocol::DNS;
    if (pkt.http) return AppProtocol::HTTP;
    if (pkt.tls)  return AppProtocol::HTTPS;
    if (pkt.icmp || pkt.icmpv6) return AppProtocol::ICMP;

    // Port-based heuristic
    uint16_t port = 0;
    if (pkt.tcp) port = std::min(pkt.tcp->src_port, pkt.tcp->dst_port);
    if (pkt.udp) port = std::min(pkt.udp->src_port, pkt.udp->dst_port);
    switch (port) {
        case 443:  return AppProtocol::HTTPS;
        case 22:   return AppProtocol::SSH;
        case 5432: return AppProtocol::Postgres;
        case 3306: return AppProtocol::MySQL;
        case 6379: return AppProtocol::Redis;
        default:   return AppProtocol::Unknown;
    }
}

// ── Background expiry loop ────────────────────────────────────────────────────
// Sweeps 1 shard per tick, spreading work over 1 second total.

void FlowEngine::expiry_loop() {
    const int tick_ms = config_.expiry_sweep_interval_ms / FlowTable::NUM_SHARDS;
    size_t shard_idx  = 0;
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(tick_ms));
        auto expired = table_.sweep_shard(shard_idx, now_ns());
        for (auto& f : expired) {
            f->tcp_state = TcpFlowState::EXPIRED;
            f->is_active = false;
            if (callback_) callback_(FlowEvent::EXPIRED, f);
        }
        shard_idx = (shard_idx + 1) % FlowTable::NUM_SHARDS;
    }
}

// ── Static helpers ────────────────────────────────────────────────────────────

bool FlowEngine::is_forward(const ParsedPacket& pkt, const FlowKey& key) noexcept {
    // "Forward" = this packet's source address matches the key's normalised src
    if (pkt.ip4) {
        uint32_t pkt_src = pkt.ip4->src_ip;
        uint32_t key_src = 0;
        std::memcpy(&key_src, key.src_addr, 4);
        return pkt_src == key_src && (pkt.tcp ? pkt.tcp->src_port : pkt.udp ? pkt.udp->src_port : 0) == key.src_port;
    }
    if (pkt.ip6) {
        return std::memcmp(pkt.ip6->src_ip_raw.data(), key.src_addr, 16) == 0;
    }
    return true;
}

int64_t FlowEngine::now_ns() noexcept {
    return std::chrono::steady_clock::now().time_since_epoch().count();
}
