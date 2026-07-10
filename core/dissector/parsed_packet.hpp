#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <array>
#include <chrono>

// ── Application-layer protocol classification ────────────────────────────────
enum class AppProtocol : uint8_t {
    Unknown = 0,
    HTTP, HTTPS, HTTP2, HTTP3,
    DNS, DNS_TLS,
    SSH, FTP, SMTP, IMAP, POP3,
    Postgres, MySQL, Redis, MongoDB,
    MQTT, WebSocket,
    ARP, ICMP, ICMPv6,
};

inline const char* app_protocol_str(AppProtocol p) {
    switch (p) {
        case AppProtocol::HTTP:      return "HTTP";
        case AppProtocol::HTTPS:     return "HTTPS";
        case AppProtocol::HTTP2:     return "HTTP/2";
        case AppProtocol::HTTP3:     return "HTTP/3";
        case AppProtocol::DNS:       return "DNS";
        case AppProtocol::DNS_TLS:   return "DNS-over-TLS";
        case AppProtocol::SSH:       return "SSH";
        case AppProtocol::FTP:       return "FTP";
        case AppProtocol::SMTP:      return "SMTP";
        case AppProtocol::IMAP:      return "IMAP";
        case AppProtocol::POP3:      return "POP3";
        case AppProtocol::Postgres:  return "PostgreSQL";
        case AppProtocol::MySQL:     return "MySQL";
        case AppProtocol::Redis:     return "Redis";
        case AppProtocol::MongoDB:   return "MongoDB";
        case AppProtocol::MQTT:      return "MQTT";
        case AppProtocol::WebSocket: return "WebSocket";
        case AppProtocol::ARP:       return "ARP";
        case AppProtocol::ICMP:      return "ICMP";
        case AppProtocol::ICMPv6:    return "ICMPv6";
        default:                     return "Unknown";
    }
}

// ── Layer 2 ──────────────────────────────────────────────────────────────────

struct EtherFields {
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ethertype = 0;      // 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP, 0x8100=VLAN
    std::string src_mac_str;     // "aa:bb:cc:dd:ee:ff" — pre-formatted for JSON
    std::string dst_mac_str;
};

struct VlanFields {
    uint16_t vlan_id         = 0;
    uint8_t  priority        = 0; // 802.1p PCP bits
    uint16_t inner_ethertype = 0;
};

struct ArpFields {
    uint16_t operation = 0;      // 1=request, 2=reply
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};

// ── Layer 3 ──────────────────────────────────────────────────────────────────

struct IPv4Fields {
    uint32_t    src_ip      = 0; // raw host-order uint32
    uint32_t    dst_ip      = 0;
    std::string src_ip_str;      // "192.168.1.1" — pre-formatted
    std::string dst_ip_str;
    uint8_t     ttl         = 0;
    uint8_t     protocol    = 0; // 6=TCP, 17=UDP, 1=ICMP
    uint16_t    total_len   = 0;
    uint16_t    id          = 0; // identification field
    uint8_t     dscp        = 0; // differentiated services (QoS class)
    uint8_t     ecn         = 0; // explicit congestion notification
    bool        df_flag     = false; // don't fragment
    bool        mf_flag     = false; // more fragments
    uint16_t    frag_offset = 0;
    bool        is_fragment = false;
    uint8_t     ihl         = 0; // header length in 32-bit words
};

struct IPv6Fields {
    // Full 128-bit addresses stored as strings (formatting via PcapPlusPlus)
    std::string src_ip_str;
    std::string dst_ip_str;
    // Raw bytes for hashing in flow keys
    std::array<uint8_t, 16> src_ip_raw{};
    std::array<uint8_t, 16> dst_ip_raw{};
    uint8_t  hop_limit     = 0;
    uint8_t  next_header   = 0; // 6=TCP, 17=UDP, 58=ICMPv6, 0=hop-by-hop ext
    uint32_t flow_label    = 0;
    uint16_t payload_len   = 0;
    uint8_t  traffic_class = 0; // DSCP + ECN packed
    uint8_t  dscp          = 0; // extracted from traffic_class
    uint8_t  ecn           = 0; // extracted from traffic_class
};

struct IcmpFields {
    uint8_t  type     = 0;
    uint8_t  code     = 0;
    uint16_t id       = 0; // for echo requests — used to match request/reply
    uint16_t seq      = 0;
    // type+code: 0/0=echo reply, 8/0=echo req, 3/*=unreachable, 11/0=TTL exceeded
};

struct IcmpV6Fields {
    uint8_t  type     = 0;
    uint8_t  code     = 0;
    uint16_t id       = 0;
    uint16_t seq      = 0;
    // type: 128=echo req, 129=echo reply, 133=RS, 134=RA, 135=NS, 136=NA
};

// ── Layer 4 ──────────────────────────────────────────────────────────────────

struct TcpFields {
    uint16_t src_port    = 0;
    uint16_t dst_port    = 0;
    uint32_t seq_num     = 0;
    uint32_t ack_num     = 0;
    uint16_t window_size = 0;
    uint8_t  data_offset = 0; // header length in 32-bit words
    uint16_t payload_len = 0; // data bytes after TCP header

    // Flags — extracted as individual bools for easy querying
    bool flag_syn = false;
    bool flag_ack = false;
    bool flag_fin = false;
    bool flag_rst = false;
    bool flag_psh = false;
    bool flag_urg = false;
    bool flag_ece = false; // ECN-Echo — congestion was experienced
    bool flag_cwr = false; // Congestion Window Reduced

    // TCP Options (present only during handshake or first segments)
    std::optional<uint16_t> mss;          // max segment size
    std::optional<uint8_t>  window_scale; // actual_window = window_size << window_scale
    std::optional<uint32_t> ts_val;       // TCP timestamp value
    std::optional<uint32_t> ts_ecr;       // TCP timestamp echo reply
    bool sack_permitted = false;
    std::vector<std::pair<uint32_t,uint32_t>> sack_blocks; // left/right edges

    // Derived — computed by the dissector from options
    uint32_t actual_window = 0; // window_size << window_scale (if known)
};

struct UdpFields {
    uint16_t src_port    = 0;
    uint16_t dst_port    = 0;
    uint16_t length      = 0;
    uint16_t payload_len = 0;
};

// ── Layer 7 ──────────────────────────────────────────────────────────────────

struct DnsFields {
    uint16_t    transaction_id = 0;
    bool        is_response    = false;
    uint8_t     rcode          = 0;  // 0=ok, 1=format err, 2=server fail, 3=nxdomain
    std::string query_name;
    uint16_t    query_type     = 0;  // 1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT
    std::vector<std::string> answers; // resolved IPs or CNAME values
    bool        is_truncated   = false;
    bool        is_recursive   = false;
    uint16_t    answer_count   = 0;
};

struct HttpFields {
    bool is_request  = false;
    bool is_response = false;

    // Request fields
    std::string method;         // GET POST PUT DELETE PATCH etc.
    std::string url;
    std::string host;
    std::string user_agent;
    std::string content_type;
    int64_t     content_length = -1;
    std::string referer;

    // Response fields
    int         status_code    = 0;  // 200, 404, 500 etc.
    std::string status_message;
    int64_t     response_size  = 0;
    bool        is_chunked     = false;

    // Both
    std::string http_version; // "1.0", "1.1"
};

struct TlsFields {
    uint8_t  record_type   = 0;  // 20=change_cipher, 21=alert, 22=handshake, 23=app_data
    uint8_t  major_version = 0;
    uint8_t  minor_version = 0;
    uint16_t length        = 0;

    // Handshake sub-type (when record_type == 22)
    uint8_t  handshake_type = 0; // 1=ClientHello, 2=ServerHello, 11=Cert, 14=Done

    // ClientHello parsed extensions
    std::string          sni;          // server name indication — domain being connected to
    std::string          alpn;         // negotiated protocol: "http/1.1", "h2", "h3"
    std::vector<uint16_t> cipher_suites;
    std::string          tls_version_str; // "TLS 1.0" ... "TLS 1.3"

    // TLS 1.3 detection: outer record claims 1.2 but inner supported_versions
    // extension says 1.3 — we detect this and set tls_version_str = "TLS 1.3"

    // Alert (when record_type == 21)
    uint8_t alert_level       = 0; // 1=warning, 2=fatal
    uint8_t alert_description = 0; // 0=close_notify, 40=handshake_fail, 42=bad_cert
};

// ── Top-level ParsedPacket ────────────────────────────────────────────────────

struct ParsedPacket {
    // Identity (copied from CapturedPacket)
    uint64_t    packet_id     = 0;
    int64_t     timestamp_ns  = 0;  // nanoseconds since epoch
    uint32_t    captured_len  = 0;
    uint32_t    original_len  = 0;
    std::string interface_name;
    bool        is_truncated  = false; // captured_len < original_len

    // Layers — present only if found and parsed successfully
    std::optional<EtherFields>  eth;
    std::optional<VlanFields>   vlan;
    std::optional<ArpFields>    arp;
    std::optional<IPv4Fields>   ip4;
    std::optional<IPv6Fields>   ip6;
    std::optional<IcmpFields>   icmp;
    std::optional<IcmpV6Fields> icmpv6;
    std::optional<TcpFields>    tcp;
    std::optional<UdpFields>    udp;
    std::optional<DnsFields>    dns;
    std::optional<HttpFields>   http;
    std::optional<TlsFields>    tls;

    // Application-layer protocol — classified by DissectorEngine
    AppProtocol app_protocol = AppProtocol::Unknown;

    // Convenience helpers
    bool has_ip()   const { return ip4.has_value() || ip6.has_value(); }
    bool has_tcp()  const { return tcp.has_value(); }
    bool has_udp()  const { return udp.has_value(); }
    bool has_dns()  const { return dns.has_value(); }
    bool has_http() const { return http.has_value(); }
    bool has_tls()  const { return tls.has_value(); }

    // 5-tuple flow key — filled once L3+L4 are parsed
    struct FlowKey {
        std::string src_ip, dst_ip;
        uint16_t    src_port = 0, dst_port = 0;
        uint8_t     protocol = 0; // IPPROTO_TCP=6, IPPROTO_UDP=17
        bool        valid    = false;

        // Canonical key: always low IP/port first (for bidirectional matching)
        std::string canonical() const {
            if (!valid) return "";
            bool swapped = (src_ip > dst_ip) ||
                           (src_ip == dst_ip && src_port > dst_port);
            if (swapped)
                return dst_ip + ":" + std::to_string(dst_port) + "->" +
                       src_ip + ":" + std::to_string(src_port) + "/" +
                       std::to_string(protocol);
            return src_ip + ":" + std::to_string(src_port) + "->" +
                   dst_ip + ":" + std::to_string(dst_port) + "/" +
                   std::to_string(protocol);
        }
    } flow_key;

    // Error tracking — records the first parse error if any layer fails
    std::string parse_error;
};
