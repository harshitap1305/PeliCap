

First, here's the overall dissector architecture — how a raw packet flows through each protocol layer:Now the second diagram — what fields you extract from TCP specifically, since it's the richest and most important protocol for your analytics:Now the complete implementation plan.
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

Now the second diagram — what fields you extract from TCP specifically, since it's the richest and most important protocol for your analytics:
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

---

## Why PcapPlusPlus makes Module 2 dramatically easier

Without PcapPlusPlus you'd write manual byte-offset parsing for every protocol — dozens of `reinterpret_cast<>` calls with magic offsets, handling endianness manually, dealing with IP options shifting offsets. PcapPlusPlus gives you typed layer objects with named accessors. `tcpLayer->getTcpHeader()->synFlag` instead of `*(buf + 13) & 0x02`. This is the entire value proposition for Module 2.

---

## The core design decision: one struct per protocol layer

Design your output as composable field structs, one per protocol layer. Never one giant flat struct — it becomes unmaintainable and wastes memory for packets that don't have certain layers.

```cpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <array>
#include <chrono>

// ── Layer 2 ──────────────────────────────────────────────────────────────────

struct EtherFields {
    std::array<uint8_t, 6> src_mac{};
    std::array<uint8_t, 6> dst_mac{};
    uint16_t ethertype = 0;        // 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP, 0x8100=VLAN
    std::string src_mac_str;       // "aa:bb:cc:dd:ee:ff" — pre-formatted for JSON
    std::string dst_mac_str;
};

struct VlanFields {
    uint16_t vlan_id       = 0;
    uint8_t  priority      = 0;    // 802.1p PCP bits
    uint16_t inner_ethertype = 0;
};

struct ArpFields {
    uint16_t operation   = 0;      // 1=request, 2=reply
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};

// ── Layer 3 ──────────────────────────────────────────────────────────────────

struct IPv4Fields {
    uint32_t    src_ip     = 0;    // raw network-order uint32
    uint32_t    dst_ip     = 0;
    std::string src_ip_str;        // "192.168.1.1" — pre-formatted
    std::string dst_ip_str;
    uint8_t     ttl        = 0;
    uint8_t     protocol   = 0;    // 6=TCP, 17=UDP, 1=ICMP
    uint16_t    total_len  = 0;
    uint16_t    id         = 0;    // identification field
    uint8_t     dscp       = 0;    // differentiated services (QoS class)
    uint8_t     ecn        = 0;    // explicit congestion notification
    bool        df_flag    = false; // don't fragment
    bool        mf_flag    = false; // more fragments
    uint16_t    frag_offset = 0;
    bool        is_fragment = false;
};

struct IPv6Fields {
    std::string src_ip_str;
    std::string dst_ip_str;
    uint8_t     hop_limit  = 0;
    uint8_t     next_header = 0;
    uint32_t    flow_label  = 0;
    uint16_t    payload_len = 0;
    uint8_t     traffic_class = 0;
};

struct IcmpFields {
    uint8_t  type = 0;
    uint8_t  code = 0;
    uint16_t id   = 0;            // for echo requests — used to match request/reply
    uint16_t seq  = 0;
    // type+code meaning: 0/0=echo reply, 8/0=echo req, 3/*=unreachable, 11/0=TTL exceeded
};

// ── Layer 4 ──────────────────────────────────────────────────────────────────

struct TcpFields {
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;
    uint32_t seq_num      = 0;
    uint32_t ack_num      = 0;
    uint16_t window_size  = 0;
    uint8_t  data_offset  = 0;    // header length in 32-bit words
    uint16_t payload_len  = 0;    // data bytes after TCP header

    // Flags — extracted as individual bools for easy querying
    bool flag_syn = false;
    bool flag_ack = false;
    bool flag_fin = false;
    bool flag_rst = false;
    bool flag_psh = false;
    bool flag_urg = false;
    bool flag_ece = false;        // ECN-Echo — congestion was experienced
    bool flag_cwr = false;        // Congestion Window Reduced

    // TCP Options (present only during handshake or first segments)
    std::optional<uint16_t> mss;           // max segment size
    std::optional<uint8_t>  window_scale;  // actual_window = window_size << window_scale
    std::optional<uint32_t> ts_val;        // TCP timestamp value
    std::optional<uint32_t> ts_ecr;        // TCP timestamp echo reply → RTT = now - ts_val
    bool sack_permitted = false;
    std::vector<std::pair<uint32_t,uint32_t>> sack_blocks; // left/right edges

    // Derived — computed by the dissector, not from the header directly
    uint32_t actual_window = 0;   // window_size << window_scale (if known)
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
    uint8_t     rcode          = 0;    // 0=ok, 1=format err, 2=server fail, 3=nxdomain
    std::string query_name;
    uint16_t    query_type     = 0;    // 1=A, 28=AAAA, 5=CNAME, 15=MX, 16=TXT
    std::vector<std::string> answers;  // resolved IPs or values
    bool        is_truncated   = false;

    // Timing — populated by DnsTracker in Module 4, not here
    // int64_t resolution_time_us = 0;
};

struct HttpFields {
    bool     is_request  = false;
    bool     is_response = false;

    // Request fields
    std::string method;            // GET POST PUT DELETE etc.
    std::string url;
    std::string host;
    std::string user_agent;
    std::string content_type;
    int64_t     content_length = -1;

    // Response fields
    int         status_code    = 0;   // 200, 404, 500 etc.
    std::string status_message;
    int64_t     response_size  = 0;
    bool        is_chunked     = false;

    // Both
    std::string http_version;  // "1.1", "2", "3"
};

struct TlsFields {
    uint8_t  record_type   = 0;   // 20=change_cipher, 21=alert, 22=handshake, 23=app_data
    uint8_t  major_version = 0;
    uint8_t  minor_version = 0;
    uint16_t length        = 0;

    // Handshake sub-type (when record_type == 22)
    uint8_t  handshake_type = 0;  // 1=ClientHello, 2=ServerHello, 11=Certificate, 14=Done

    // ClientHello extras
    std::string         sni;      // server name indication — which domain they're connecting to
    std::vector<uint16_t> cipher_suites;
    std::string         tls_version_str; // "TLS 1.2", "TLS 1.3"

    // Alert (when record_type == 21)
    uint8_t alert_level       = 0; // 1=warning, 2=fatal
    uint8_t alert_description = 0; // 0=close_notify, 40=handshake_fail, 42=bad_cert etc.
};

// ── Top-level ParsedPacket ────────────────────────────────────────────────────

struct ParsedPacket {
    uint64_t packet_id   = 0;
    int64_t  timestamp_ns = 0;    // nanoseconds since epoch
    uint32_t captured_len = 0;
    uint32_t original_len = 0;
    std::string interface_name;
    bool     is_truncated = false; // captured_len < original_len

    // Present only if the corresponding layer was found and parsed
    std::optional<EtherFields> eth;
    std::optional<VlanFields>  vlan;
    std::optional<ArpFields>   arp;
    std::optional<IPv4Fields>  ip4;
    std::optional<IPv6Fields>  ip6;
    std::optional<IcmpFields>  icmp;
    std::optional<TcpFields>   tcp;
    std::optional<UdpFields>   udp;
    std::optional<DnsFields>   dns;
    std::optional<HttpFields>  http;
    std::optional<TlsFields>   tls;

    // Convenience helpers
    bool has_tcp()  const { return tcp.has_value(); }
    bool has_dns()  const { return dns.has_value(); }
    bool has_http() const { return http.has_value(); }
    bool has_tls()  const { return tls.has_value(); }

    // The 5-tuple flow key — filled in once L3+L4 are parsed
    struct FlowKey {
        std::string src_ip, dst_ip;
        uint16_t    src_port = 0, dst_port = 0;
        uint8_t     protocol = 0;
        bool        valid    = false;
    } flow_key;
};
```

The `std::optional<>` on every layer is the critical design choice. A UDP packet doesn't have a `TcpFields`. An ARP packet has no IP layer. Using optionals means your downstream code always asks `if (pkt.tcp)` before accessing fields — no silent zero-reads from unpopulated structs.

---

## The DissectorEngine class

```cpp
#pragma once
#include "parsed_packet.hpp"
#include "../capture/packet.hpp"          // CapturedPacket from Module 1

// PcapPlusPlus headers
#include <Packet.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <HttpLayer.h>
#include <ArpLayer.h>
#include <IcmpLayer.h>
#include <VlanLayer.h>
#include <TcpReassembly.h>

class DissectorEngine {
public:
    // Main entry point — takes your Module 1 struct, returns fully parsed packet
    static ParsedPacket dissect(const CapturedPacket& raw);

private:
    static void parse_ethernet (pcpp::EthLayer*,   ParsedPacket&);
    static void parse_vlan     (pcpp::VlanLayer*,  ParsedPacket&);
    static void parse_arp      (pcpp::ArpLayer*,   ParsedPacket&);
    static void parse_ipv4     (pcpp::IPv4Layer*,  ParsedPacket&);
    static void parse_ipv6     (pcpp::IPv6Layer*,  ParsedPacket&);
    static void parse_icmp     (pcpp::IcmpLayer*,  ParsedPacket&);
    static void parse_tcp      (pcpp::TcpLayer*,   ParsedPacket&);
    static void parse_udp      (pcpp::UdpLayer*,   ParsedPacket&);
    static void parse_dns      (pcpp::DnsLayer*,   ParsedPacket&);
    static void parse_http_req (pcpp::HttpRequestLayer*,  ParsedPacket&);
    static void parse_http_res (pcpp::HttpResponseLayer*, ParsedPacket&);
    static void parse_tls      (pcpp::Layer*,      ParsedPacket&); // manual — see below
    static void build_flow_key (ParsedPacket&);

    static std::string mac_to_string(const pcpp::MacAddress&);
};
```

```cpp
#include "dissector_engine.hpp"
#include <sstream>
#include <iomanip>

ParsedPacket DissectorEngine::dissect(const CapturedPacket& raw) {
    ParsedPacket out;
    out.packet_id    = raw.id;
    out.timestamp_ns = raw.timestamp.count();
    out.captured_len = raw.captured_len;
    out.original_len = raw.original_len;
    out.interface_name = raw.interface_name;
    out.is_truncated = (raw.captured_len < raw.original_len);

    // Hand raw bytes to PcapPlusPlus — it parses every layer automatically
    pcpp::RawPacket raw_pkt(
        raw.raw.data(),
        static_cast<int>(raw.raw.size()),
        // Convert nanoseconds to timeval
        timeval{ static_cast<time_t>(raw.timestamp.count() / 1'000'000'000LL),
                 static_cast<suseconds_t>((raw.timestamp.count() % 1'000'000'000LL) / 1000LL) },
        false,                          // don't delete data — we own it
        static_cast<pcpp::LinkLayerType>(raw.link_type)
    );
    pcpp::Packet parsed_pkt(&raw_pkt);

    // Walk layers — PcapPlusPlus builds a linked list of typed Layer objects
    for (pcpp::Layer* layer = parsed_pkt.getFirstLayer();
         layer != nullptr;
         layer = layer->getNextLayer())
    {
        switch (layer->getProtocol()) {
            case pcpp::Ethernet:
                parse_ethernet(dynamic_cast<pcpp::EthLayer*>(layer), out);
                break;
            case pcpp::VLAN:
                parse_vlan(dynamic_cast<pcpp::VlanLayer*>(layer), out);
                break;
            case pcpp::ARP:
                parse_arp(dynamic_cast<pcpp::ArpLayer*>(layer), out);
                break;
            case pcpp::IPv4:
                parse_ipv4(dynamic_cast<pcpp::IPv4Layer*>(layer), out);
                break;
            case pcpp::IPv6:
                parse_ipv6(dynamic_cast<pcpp::IPv6Layer*>(layer), out);
                break;
            case pcpp::ICMP:
                parse_icmp(dynamic_cast<pcpp::IcmpLayer*>(layer), out);
                break;
            case pcpp::TCP:
                parse_tcp(dynamic_cast<pcpp::TcpLayer*>(layer), out);
                break;
            case pcpp::UDP:
                parse_udp(dynamic_cast<pcpp::UdpLayer*>(layer), out);
                break;
            case pcpp::DNS:
                parse_dns(dynamic_cast<pcpp::DnsLayer*>(layer), out);
                break;
            case pcpp::HTTP:
                if (auto* req = dynamic_cast<pcpp::HttpRequestLayer*>(layer))
                    parse_http_req(req, out);
                else if (auto* res = dynamic_cast<pcpp::HttpResponseLayer*>(layer))
                    parse_http_res(res, out);
                break;
            case pcpp::SSL:
                parse_tls(layer, out);
                break;
            default:
                break;
        }
    }

    build_flow_key(out);
    return out;
}
```

---

## Layer parsers — the key ones in full

### TCP (most important — most fields matter for analytics)

```cpp
void DissectorEngine::parse_tcp(pcpp::TcpLayer* l, ParsedPacket& out) {
    TcpFields f;
    auto* hdr = l->getTcpHeader();

    f.src_port    = ntohs(hdr->portSrc);
    f.dst_port    = ntohs(hdr->portDst);
    f.seq_num     = ntohl(hdr->sequenceNumber);
    f.ack_num     = ntohl(hdr->ackNumber);
    f.window_size = ntohs(hdr->windowSize);
    f.data_offset = hdr->dataOffset;
    f.payload_len = static_cast<uint16_t>(l->getLayerPayloadSize());

    // Flags — PcapPlusPlus exposes each as a bitfield
    f.flag_syn = hdr->synFlag;
    f.flag_ack = hdr->ackFlag;
    f.flag_fin = hdr->finFlag;
    f.flag_rst = hdr->rstFlag;
    f.flag_psh = hdr->pshFlag;
    f.flag_urg = hdr->urgFlag;
    f.flag_ece = hdr->eceFlag;
    f.flag_cwr = hdr->cwrFlag;

    // TCP Options — iterate through them
    pcpp::TcpOption opt = l->getFirstTcpOption();
    while (opt.isNotNull()) {
        switch (opt.getTcpOptionType()) {
            case pcpp::TcpOptionType::PCPP_TCPOPT_MSS:
                if (opt.getValueLength() >= 2) {
                    uint16_t mss_val;
                    memcpy(&mss_val, opt.getValue(), 2);
                    f.mss = ntohs(mss_val);
                }
                break;

            case pcpp::TcpOptionType::PCPP_TCPOPT_WINDOW:
                if (opt.getValueLength() >= 1) {
                    f.window_scale = *opt.getValue();
                    // Now we can compute actual window
                    f.actual_window = static_cast<uint32_t>(f.window_size)
                                      << *f.window_scale;
                }
                break;

            case pcpp::TcpOptionType::PCPP_TCPOPT_TIMESTAMP:
                if (opt.getValueLength() >= 8) {
                    uint32_t tsval, tsecr;
                    memcpy(&tsval, opt.getValue(),     4);
                    memcpy(&tsecr, opt.getValue() + 4, 4);
                    f.ts_val = ntohl(tsval);
                    f.ts_ecr = ntohl(tsecr);
                    // RTT can be computed in Module 4 as:
                    // rtt_ms = (now_ts_val - echo_ts_ecr) / clock_hz
                }
                break;

            case pcpp::TcpOptionType::PCPP_TCPOPT_SACK_PERM:
                f.sack_permitted = true;
                break;

            case pcpp::TcpOptionType::PCPP_TCPOPT_SACK: {
                // Each SACK block is 8 bytes: left_edge (4) + right_edge (4)
                size_t num_blocks = opt.getValueLength() / 8;
                for (size_t i = 0; i < num_blocks; ++i) {
                    uint32_t left, right;
                    memcpy(&left,  opt.getValue() + i * 8,     4);
                    memcpy(&right, opt.getValue() + i * 8 + 4, 4);
                    f.sack_blocks.emplace_back(ntohl(left), ntohl(right));
                }
                break;
            }
            default: break;
        }
        opt = l->getNextTcpOption(opt);
    }

    out.tcp = std::move(f);
}
```

### DNS (second most important for latency analysis)

```cpp
void DissectorEngine::parse_dns(pcpp::DnsLayer* l, ParsedPacket& out) {
    DnsFields f;
    auto* hdr = l->getDnsHeader();

    f.transaction_id = ntohs(hdr->transactionID);
    f.is_response    = (hdr->queryOrResponse == 1);
    f.rcode          = hdr->responseCode;
    f.is_truncated   = (hdr->truncation == 1);

    // Extract query name and type
    pcpp::DnsQuery* query = l->getFirstQuery();
    if (query) {
        f.query_name = query->getName();
        f.query_type = static_cast<uint16_t>(query->getDnsType());
    }

    // Extract all answer records
    pcpp::DnsResource* answer = l->getFirstAnswer();
    while (answer) {
        // getDnsRdata() gives you the resolved value as a string
        f.answers.push_back(answer->getData()->toString());
        answer = l->getNextAnswer(answer);
    }

    out.dns = std::move(f);
}
```

### TLS (manual — PcapPlusPlus parses record headers but not ClientHello internals)

This is where you need to go a little deeper manually, because PcapPlusPlus gives you the TLS record type/version/length but doesn't parse the SNI extension inside `ClientHello`. SNI is critical — it tells you the domain even on encrypted traffic.

```cpp
void DissectorEngine::parse_tls(pcpp::Layer* l, ParsedPacket& out) {
    TlsFields f;
    const uint8_t* data = l->getData();
    size_t         len  = l->getDataLen();

    if (len < 5) return;

    f.record_type   = data[0];
    f.major_version = data[1];
    f.minor_version = data[2];
    f.length        = (data[3] << 8) | data[4];

    // Map version bytes to readable string
    if      (f.major_version == 3 && f.minor_version == 1) f.tls_version_str = "TLS 1.0";
    else if (f.major_version == 3 && f.minor_version == 2) f.tls_version_str = "TLS 1.1";
    else if (f.major_version == 3 && f.minor_version == 3) f.tls_version_str = "TLS 1.2";
    else if (f.major_version == 3 && f.minor_version == 4) f.tls_version_str = "TLS 1.3";

    // Record type 22 = Handshake
    if (f.record_type == 22 && len >= 6) {
        f.handshake_type = data[5];

        // Handshake type 1 = ClientHello — parse extensions to find SNI
        if (f.handshake_type == 1 && len > 43) {
            // ClientHello layout after handshake header:
            //   version(2) + random(32) + session_id_len(1) + session_id(var)
            //   + cipher_suites_len(2) + cipher_suites(var)
            //   + compression_methods_len(1) + compression_methods(var)
            //   + extensions_len(2) + extensions(var)
            size_t offset = 6 + 4;   // record header(5) + handshake header(4) skipped
            // Skip version + random
            offset += 2 + 32;
            if (offset >= len) { out.tls = std::move(f); return; }
            // Skip session ID
            uint8_t sid_len = data[offset++];
            offset += sid_len;
            // Skip cipher suites
            if (offset + 2 > len) { out.tls = std::move(f); return; }
            uint16_t cs_len = (data[offset] << 8) | data[offset+1];
            offset += 2 + cs_len;
            // Skip compression methods
            if (offset >= len) { out.tls = std::move(f); return; }
            uint8_t cm_len = data[offset++];
            offset += cm_len;
            // Extensions
            if (offset + 2 > len) { out.tls = std::move(f); return; }
            uint16_t ext_total = (data[offset] << 8) | data[offset+1];
            offset += 2;
            size_t ext_end = std::min(offset + ext_total, len);

            while (offset + 4 <= ext_end) {
                uint16_t ext_type = (data[offset] << 8) | data[offset+1];
                uint16_t ext_len  = (data[offset+2] << 8) | data[offset+3];
                offset += 4;
                if (ext_type == 0x0000 && offset + 5 <= ext_end) {
                    // SNI extension: list_len(2) + type(1) + name_len(2) + name
                    uint16_t name_len = (data[offset+3] << 8) | data[offset+4];
                    if (offset + 5 + name_len <= ext_end) {
                        f.sni.assign(reinterpret_cast<const char*>(data + offset + 5),
                                     name_len);
                    }
                }
                offset += ext_len;
            }
        }

        // Alert record
        if (f.record_type == 21 && len >= 7) {
            f.alert_level       = data[5];
            f.alert_description = data[6];
        }
    }

    out.tls = std::move(f);
}
```

---

## Flow key builder

Every downstream module needs the 5-tuple. Build it once here so nobody else has to:

```cpp
void DissectorEngine::build_flow_key(ParsedPacket& out) {
    auto& fk = out.flow_key;

    // L3
    if (out.ip4) {
        fk.src_ip   = out.ip4->src_ip_str;
        fk.dst_ip   = out.ip4->dst_ip_str;
        fk.protocol = out.ip4->protocol;
        fk.valid    = true;
    } else if (out.ip6) {
        fk.src_ip   = out.ip6->src_ip_str;
        fk.dst_ip   = out.ip6->dst_ip_str;
        fk.valid    = true;
    }

    // L4
    if (out.tcp) {
        fk.src_port = out.tcp->src_port;
        fk.dst_port = out.tcp->dst_port;
    } else if (out.udp) {
        fk.src_port = out.udp->src_port;
        fk.dst_port = out.udp->dst_port;
    }
}
```

---

## Protocol identification by port

When PcapPlusPlus doesn't identify an application layer protocol (e.g., non-standard ports), use port heuristics as a fallback:

```cpp
enum class AppProtocol {
    Unknown, HTTP, HTTPS, DNS, SSH, FTP, SMTP, IMAP, POP3,
    Postgres, MySQL, Redis, MongoDB, MQTT, WebSocket
};

AppProtocol identify_by_port(uint16_t port) {
    switch (port) {
        case 80:   case 8080: case 8000: return AppProtocol::HTTP;
        case 443:  case 8443:            return AppProtocol::HTTPS;
        case 53:                          return AppProtocol::DNS;
        case 22:                          return AppProtocol::SSH;
        case 21:                          return AppProtocol::FTP;
        case 25:   case 587:              return AppProtocol::SMTP;
        case 5432:                        return AppProtocol::Postgres;
        case 3306:                        return AppProtocol::MySQL;
        case 6379:                        return AppProtocol::Redis;
        case 27017:                       return AppProtocol::MongoDB;
        case 1883: case 8883:             return AppProtocol::MQTT;
        default:                          return AppProtocol::Unknown;
    }
}
```

---

## JSON serialization for the API

Every `ParsedPacket` needs to serialize to JSON for your REST API. Use `nlohmann/json`:

```cpp
#include <nlohmann/json.hpp>

nlohmann::json to_json(const ParsedPacket& p) {
    nlohmann::json j;
    j["id"]           = p.packet_id;
    j["timestamp_ns"] = p.timestamp_ns;
    j["captured_len"] = p.captured_len;
    j["original_len"] = p.original_len;
    j["interface"]    = p.interface_name;
    j["truncated"]    = p.is_truncated;

    if (p.eth) {
        j["eth"]["src"]       = p.eth->src_mac_str;
        j["eth"]["dst"]       = p.eth->dst_mac_str;
        j["eth"]["ethertype"] = p.eth->ethertype;
    }
    if (p.ip4) {
        j["ip"]["src"]      = p.ip4->src_ip_str;
        j["ip"]["dst"]      = p.ip4->dst_ip_str;
        j["ip"]["ttl"]      = p.ip4->ttl;
        j["ip"]["protocol"] = p.ip4->protocol;
        j["ip"]["dscp"]     = p.ip4->dscp;
        j["ip"]["ecn"]      = p.ip4->ecn;
    }
    if (p.tcp) {
        j["tcp"]["src_port"]  = p.tcp->src_port;
        j["tcp"]["dst_port"]  = p.tcp->dst_port;
        j["tcp"]["seq"]       = p.tcp->seq_num;
        j["tcp"]["ack"]       = p.tcp->ack_num;
        j["tcp"]["window"]    = p.tcp->window_size;
        j["tcp"]["flags"]     = {
            {"syn", p.tcp->flag_syn}, {"ack", p.tcp->flag_ack},
            {"fin", p.tcp->flag_fin}, {"rst", p.tcp->flag_rst},
            {"psh", p.tcp->flag_psh}, {"ece", p.tcp->flag_ece}
        };
        if (p.tcp->mss)          j["tcp"]["mss"]          = *p.tcp->mss;
        if (p.tcp->window_scale) j["tcp"]["window_scale"] = *p.tcp->window_scale;
        if (p.tcp->ts_val)       j["tcp"]["ts_val"]       = *p.tcp->ts_val;
        if (p.tcp->sack_permitted) j["tcp"]["sack"] = true;
    }
    if (p.dns) {
        j["dns"]["query"]       = p.dns->query_name;
        j["dns"]["type"]        = p.dns->query_type;
        j["dns"]["is_response"] = p.dns->is_response;
        j["dns"]["rcode"]       = p.dns->rcode;
        j["dns"]["answers"]     = p.dns->answers;
    }
    if (p.http) {
        if (p.http->is_request) {
            j["http"]["method"] = p.http->method;
            j["http"]["url"]    = p.http->url;
            j["http"]["host"]   = p.http->host;
        } else {
            j["http"]["status"] = p.http->status_code;
            j["http"]["size"]   = p.http->response_size;
        }
    }
    if (p.tls) {
        j["tls"]["version"]    = p.tls->tls_version_str;
        j["tls"]["record"]     = p.tls->record_type;
        j["tls"]["handshake"]  = p.tls->handshake_type;
        if (!p.tls->sni.empty()) j["tls"]["sni"] = p.tls->sni;
    }
    if (p.flow_key.valid) {
        j["flow"]["src"]      = p.flow_key.src_ip + ":" + std::to_string(p.flow_key.src_port);
        j["flow"]["dst"]      = p.flow_key.dst_ip + ":" + std::to_string(p.flow_key.dst_port);
        j["flow"]["protocol"] = p.flow_key.protocol;
    }
    return j;
}
```

---

## CMakeLists.txt additions for Module 2

```cmake
find_package(PcapPlusPlus REQUIRED)

target_sources(network_copilot PRIVATE
    core/dissector/dissector_engine.cpp
    core/dissector/parsed_packet.hpp
    core/dissector/serializer.cpp
)

target_link_libraries(network_copilot PRIVATE
    PcapPlusPlus::PcapPlusPlus
    nlohmann_json::nlohmann_json
)
```

---

## Implementation order — do it in this sequence

Start with just getting any field out at all, then expand:

1. `EtherFields` + `IPv4Fields` — these exist in almost every packet; get them working and printing to stdout first
2. `TcpFields` without options — ports, seq, ack, flags; verify with a known PCAP
3. `TcpFields` options — MSS, timestamps, window scale; test against a `wget` capture
4. `UdpFields` + `DnsFields` — run `dig google.com` while capturing to test
5. `HttpFields` — capture `curl http://example.com` (HTTP/1.1, not HTTPS) to test
6. `TlsFields` with SNI — capture `curl https://example.com` and verify SNI extracts "example.com"
7. Flow key builder — verify it produces the same key for both directions of the same connection
8. JSON serializer — verify the API returns correct JSON for each layer

The reason for this order: each step can be independently verified with a simple `curl` or `ping` command. You never have to guess whether parsing is correct — you capture known traffic and check the output.

---

Module 2 feeds directly into Module 3 (flow reconstruction) — every `ParsedPacket` with a valid `flow_key` gets handed to the `FlowEngine`. Want me to dive into Module 3 next?