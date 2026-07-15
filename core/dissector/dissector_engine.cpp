#include "dissector_engine.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept>

// ── Helpers ──────────────────────────────────────────────────────────────────

std::string DissectorEngine::mac_to_string(const pcpp::MacAddress& mac) noexcept {
    try {
        return mac.toString();
    } catch (...) { return ""; }
}

// ── Main entry point ─────────────────────────────────────────────────────────

ParsedPacket DissectorEngine::dissect(const CapturedPacket& raw) noexcept {
    ParsedPacket out;
    out.packet_id     = raw.id;
    out.timestamp_ns  = raw.timestamp.count();
    out.captured_len  = raw.captured_len;
    out.original_len  = raw.original_len;
    out.interface_name= raw.interface_name;
    out.session_id    = raw.session_id;
    out.is_truncated  = (raw.captured_len < raw.original_len);

    try {
        timeval tv{
            static_cast<time_t>(raw.timestamp.count() / 1'000'000'000LL),
            static_cast<suseconds_t>((raw.timestamp.count() % 1'000'000'000LL) / 1000LL)
        };
        pcpp::RawPacket rp(raw.raw.data(), static_cast<int>(raw.raw.size()),
                           tv, false,
                           static_cast<pcpp::LinkLayerType>(raw.link_type));
        pcpp::Packet pkt(&rp);

        for (pcpp::Layer* l = pkt.getFirstLayer(); l; l = l->getNextLayer()) {
            auto proto = l->getProtocol();
            if      (proto == pcpp::Ethernet) parse_ethernet(dynamic_cast<pcpp::EthLayer*>(l), out);
            else if (proto == pcpp::VLAN)     parse_vlan(dynamic_cast<pcpp::VlanLayer*>(l), out);
            else if (proto == pcpp::ARP)      parse_arp(dynamic_cast<pcpp::ArpLayer*>(l), out);
            else if (proto == pcpp::IPv4)     parse_ipv4(dynamic_cast<pcpp::IPv4Layer*>(l), out);
            else if (proto == pcpp::IPv6)     parse_ipv6(dynamic_cast<pcpp::IPv6Layer*>(l), out);
            else if (proto == pcpp::ICMP)     parse_icmp(dynamic_cast<pcpp::IcmpLayer*>(l), out);
            else if (proto == pcpp::ICMPv6)   parse_icmpv6(dynamic_cast<pcpp::IcmpV6Layer*>(l), out);
            else if (proto == pcpp::TCP)      parse_tcp(dynamic_cast<pcpp::TcpLayer*>(l), out);
            else if (proto == pcpp::UDP)      parse_udp(dynamic_cast<pcpp::UdpLayer*>(l), out);
            else if (proto == pcpp::DNS)      parse_dns(dynamic_cast<pcpp::DnsLayer*>(l), out);
            else if (proto == pcpp::HTTP) {
                if (auto* req = dynamic_cast<pcpp::HttpRequestLayer*>(l))  parse_http_req(req, out);
                else if (auto* res = dynamic_cast<pcpp::HttpResponseLayer*>(l)) parse_http_res(res, out);
            }
            else if (proto == pcpp::SSL)      parse_tls(dynamic_cast<pcpp::SSLLayer*>(l), out);
        }
    } catch (const std::exception& e) {
        out.parse_error = e.what();
    } catch (...) {
        out.parse_error = "unknown exception during dissection";
    }

    build_flow_key(out);
    classify_app_protocol(out);
    return out;
}

// ── Layer 2 ──────────────────────────────────────────────────────────────────

void DissectorEngine::parse_ethernet(pcpp::EthLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        EtherFields f;
        auto* hdr = l->getEthHeader();
        std::memcpy(f.src_mac.data(), hdr->srcMac, 6);
        std::memcpy(f.dst_mac.data(), hdr->dstMac, 6);
        f.ethertype   = ntohs(hdr->etherType);
        f.src_mac_str = mac_to_string(l->getSourceMac());
        f.dst_mac_str = mac_to_string(l->getDestMac());
        out.eth = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_vlan(pcpp::VlanLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        VlanFields f;
        f.vlan_id         = l->getVlanID();
        f.priority        = l->getPriority();
        f.inner_ethertype = ntohs(l->getVlanHeader()->etherType);
        out.vlan = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_arp(pcpp::ArpLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        ArpFields f;
        auto* hdr = l->getArpHeader();
        f.operation  = ntohs(hdr->hardwareType) == 1 ? ntohs(hdr->protocolType) : 0;
        f.operation  = ntohs(hdr->opcode);
        f.sender_mac = mac_to_string(l->getSenderMacAddress());
        f.sender_ip  = l->getSenderIpAddr().toString();
        f.target_mac = mac_to_string(l->getTargetMacAddress());
        f.target_ip  = l->getTargetIpAddr().toString();
        out.arp = std::move(f);
    } catch (...) {}
}

// ── Layer 3 ──────────────────────────────────────────────────────────────────

void DissectorEngine::parse_ipv4(pcpp::IPv4Layer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        IPv4Fields f;
        auto* hdr = l->getIPv4Header();
        f.src_ip      = ntohl(hdr->ipSrc);
        f.dst_ip      = ntohl(hdr->ipDst);
        f.src_ip_str  = l->getSrcIPAddress().toString();
        f.dst_ip_str  = l->getDstIPAddress().toString();
        f.ttl         = hdr->timeToLive;
        f.protocol    = hdr->protocol;
        f.total_len   = ntohs(hdr->totalLength);
        f.id          = ntohs(hdr->ipId);
        f.ihl         = hdr->internetHeaderLength;
        uint8_t dscp_ecn = hdr->typeOfService;
        f.dscp        = (dscp_ecn >> 2) & 0x3F;
        f.ecn         = dscp_ecn & 0x03;
        uint16_t flags_frag = ntohs(hdr->fragmentOffset);
        f.df_flag     = (flags_frag & 0x4000) != 0;
        f.mf_flag     = (flags_frag & 0x2000) != 0;
        f.frag_offset = (flags_frag & 0x1FFF) * 8;
        f.is_fragment = f.mf_flag || f.frag_offset > 0;
        out.ip4 = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_ipv6(pcpp::IPv6Layer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        IPv6Fields f;
        f.src_ip_str   = l->getSrcIPAddress().toString();
        f.dst_ip_str   = l->getDstIPAddress().toString();
        auto* hdr      = l->getIPv6Header();
        f.hop_limit    = hdr->hopLimit;
        f.next_header  = hdr->nextHeader;
        f.payload_len  = ntohs(hdr->payloadLength);
        // Flow label: 20 bits starting at byte 1 of header (after version+TC)
        f.flow_label   = (static_cast<uint32_t>(hdr->flowLabel[0] & 0x0F) << 16) |
                         (static_cast<uint32_t>(hdr->flowLabel[1]) << 8)          |
                          static_cast<uint32_t>(hdr->flowLabel[2]);
        uint8_t tc     = ((hdr->trafficClass & 0x0F) << 4) |
                         ((hdr->flowLabel[0] & 0xF0) >> 4);
        f.traffic_class= tc;
        f.dscp         = (tc >> 2) & 0x3F;
        f.ecn          = tc & 0x03;
        // Copy raw address bytes for flow key hashing
        std::memcpy(f.src_ip_raw.data(), hdr->ipSrc, 16);
        std::memcpy(f.dst_ip_raw.data(), hdr->ipDst, 16);
        out.ip6 = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_icmp(pcpp::IcmpLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        IcmpFields f;
        auto* hdr = l->getIcmpHeader();
        f.type = hdr->type;
        f.code = hdr->code;
        // id/seq live in the echo-specific data
        if ((f.type == 8 || f.type == 0) && l->getDataLen() >= 8) {
            const uint8_t* d = l->getData();
            f.id  = ntohs(*reinterpret_cast<const uint16_t*>(d + 4));
            f.seq = ntohs(*reinterpret_cast<const uint16_t*>(d + 6));
        }
        out.icmp = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_icmpv6(pcpp::IcmpV6Layer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        IcmpV6Fields f;
        // getIcmpv6Header() is private in 25.05 — access raw bytes directly
        const uint8_t* d = l->getData();
        size_t len = l->getDataLen();
        if (!d || len < 4) return;
        f.type = d[0];
        f.code = d[1];
        if ((f.type == 128 || f.type == 129) && len >= 8) {
            f.id  = ntohs(*reinterpret_cast<const uint16_t*>(d + 4));
            f.seq = ntohs(*reinterpret_cast<const uint16_t*>(d + 6));
        }
        out.icmpv6 = std::move(f);
    } catch (...) {}
}

// ── Layer 4 ──────────────────────────────────────────────────────────────────

void DissectorEngine::parse_tcp(pcpp::TcpLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        TcpFields f;
        auto* hdr     = l->getTcpHeader();
        f.src_port    = ntohs(hdr->portSrc);
        f.dst_port    = ntohs(hdr->portDst);
        f.seq_num     = ntohl(hdr->sequenceNumber);
        f.ack_num     = ntohl(hdr->ackNumber);
        f.window_size = ntohs(hdr->windowSize);
        f.data_offset = hdr->dataOffset;
        f.payload_len = static_cast<uint16_t>(l->getLayerPayloadSize());
        f.flag_syn    = hdr->synFlag;
        f.flag_ack    = hdr->ackFlag;
        f.flag_fin    = hdr->finFlag;
        f.flag_rst    = hdr->rstFlag;
        f.flag_psh    = hdr->pshFlag;
        f.flag_urg    = hdr->urgFlag;
        f.flag_ece    = hdr->eceFlag;
        f.flag_cwr    = hdr->cwrFlag;

        // Use numeric option type constants to avoid deprecated enum names in 25.05
        // and getRecordLen()-2 instead of removed getValueLength()
        for (pcpp::TcpOption opt = l->getFirstTcpOption();
             opt.isNotNull();
             opt = l->getNextTcpOption(opt))
        {
            uint8_t opt_type = static_cast<uint8_t>(opt.getTcpOptionEnumType());
            size_t rec_len = opt.getTotalSize();
            // Only options with type+length+value format have rec_len > 1
            if (rec_len < 2) continue;
            size_t vlen = rec_len - 2;
            const uint8_t* v = opt.getValue();
            if (!v && vlen > 0) continue;
            switch (opt_type) {
                case 2: // MSS
                    if (vlen >= 2) { uint16_t m; std::memcpy(&m, v, 2); f.mss = ntohs(m); }
                    break;
                case 3: // Window scale
                    if (vlen >= 1) {
                        f.window_scale  = *v;
                        f.actual_window = static_cast<uint32_t>(f.window_size) << *v;
                    }
                    break;
                case 8: // Timestamp
                    if (vlen >= 8) {
                        uint32_t tsv, tse;
                        std::memcpy(&tsv, v,     4);
                        std::memcpy(&tse, v + 4, 4);
                        f.ts_val = ntohl(tsv);
                        f.ts_ecr = ntohl(tse);
                    }
                    break;
                case 4: // SACK permitted
                    f.sack_permitted = true;
                    break;
                case 5: { // SACK blocks
                    size_t nb = vlen / 8;
                    for (size_t i = 0; i < nb; i++) {
                        uint32_t l2, r;
                        std::memcpy(&l2, v + i*8,     4);
                        std::memcpy(&r,  v + i*8 + 4, 4);
                        f.sack_blocks.emplace_back(ntohl(l2), ntohl(r));
                    }
                    break;
                }
                default: break;
            }
        }
        out.tcp = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_udp(pcpp::UdpLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        UdpFields f;
        auto* hdr    = l->getUdpHeader();
        f.src_port   = ntohs(hdr->portSrc);
        f.dst_port   = ntohs(hdr->portDst);
        f.length     = ntohs(hdr->length);
        f.payload_len= static_cast<uint16_t>(l->getLayerPayloadSize());
        out.udp = std::move(f);
    } catch (...) {}
}

// ── Layer 7 ──────────────────────────────────────────────────────────────────

void DissectorEngine::parse_dns(pcpp::DnsLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        DnsFields f;
        auto* hdr         = l->getDnsHeader();
        f.transaction_id  = ntohs(hdr->transactionID);
        f.is_response     = (hdr->queryOrResponse == 1);
        f.rcode           = hdr->responseCode;
        f.is_truncated    = (hdr->truncation == 1);
        f.is_recursive    = (hdr->recursionDesired == 1);
        f.answer_count    = ntohs(hdr->numberOfAnswers);

        if (auto* q = l->getFirstQuery()) {
            f.query_name = q->getName();
            f.query_type = static_cast<uint16_t>(q->getDnsType());
        }
        for (auto* a = l->getFirstAnswer(); a; a = l->getNextAnswer(a)) {
            try { f.answers.push_back(a->getData()->toString()); } catch (...) {}
        }
        out.dns = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_http_req(pcpp::HttpRequestLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        HttpFields f;
        f.is_request  = true;
        f.method      = l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpGET    ? "GET"
                      : l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpPOST   ? "POST"
                      : l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpPUT    ? "PUT"
                      : l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpDELETE ? "DELETE"
                      : l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpPATCH  ? "PATCH"
                      : l->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpHEAD   ? "HEAD"
                      : "OTHER";
        f.url         = l->getFirstLine()->getUri();
        f.http_version= l->getFirstLine()->getVersion() == pcpp::OneDotOne ? "1.1" : "1.0";

        if (auto* h = l->getFieldByName("Host"))
            f.host = h->getFieldValue();
        if (auto* ua = l->getFieldByName("User-Agent"))
            f.user_agent = ua->getFieldValue();
        if (auto* ref = l->getFieldByName("Referer"))
            f.referer = ref->getFieldValue();
        if (auto* ct = l->getFieldByName("Content-Type"))
            f.content_type = ct->getFieldValue();
        if (auto* cl = l->getFieldByName("Content-Length"))
            try { f.content_length = std::stoll(cl->getFieldValue()); } catch (...) {}

        out.http = std::move(f);
    } catch (...) {}
}

void DissectorEngine::parse_http_res(pcpp::HttpResponseLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        HttpFields f;
        f.is_response   = true;
        f.status_code   = static_cast<int>(l->getFirstLine()->getStatusCode());
        f.status_message= l->getFirstLine()->getStatusCodeString();
        f.http_version  = l->getFirstLine()->getVersion() == pcpp::OneDotOne ? "1.1" : "1.0";
        f.response_size = static_cast<int64_t>(l->getLayerPayloadSize());
        if (auto* te = l->getFieldByName("Transfer-Encoding"))
            f.is_chunked = (te->getFieldValue().find("chunked") != std::string::npos);
        out.http = std::move(f);
    } catch (...) {}
}

// ── TLS + extensions ─────────────────────────────────────────────────────────

void DissectorEngine::parse_tls_sni(const uint8_t* d, uint16_t len, TlsFields& f) noexcept {
    // SNI list: list_len(2) + type(1) + name_len(2) + name
    if (len < 5) return;
    uint16_t name_len = (d[3] << 8) | d[4];
    if (5 + name_len > len) return;
    f.sni.assign(reinterpret_cast<const char*>(d + 5), name_len);
}

void DissectorEngine::parse_tls_alpn(const uint8_t* d, uint16_t len, TlsFields& f) noexcept {
    // ALPN: proto_list_len(2) + proto_len(1) + proto
    if (len < 4) return;
    uint16_t list_len = (d[0] << 8) | d[1];
    if (list_len < 2 || list_len + 2u > len) return;
    uint8_t  proto_len = d[2];
    if (proto_len == 0 || proto_len + 3u > len) return;
    f.alpn.assign(reinterpret_cast<const char*>(d + 3), proto_len);
}

void DissectorEngine::parse_tls_supported_versions(const uint8_t* d, uint16_t len, TlsFields& f) noexcept {
    // In ClientHello: list_len(1) + versions(2 each)
    if (len < 3) return;
    uint8_t vlist_len = d[0];
    for (uint8_t i = 0; i + 2 <= vlist_len && i + 2 < len; i += 2) {
        uint16_t ver = (d[1+i] << 8) | d[2+i];
        if (ver == 0x0304) { f.tls_version_str = "TLS 1.3"; return; }
    }
}

void DissectorEngine::parse_tls(pcpp::SSLLayer* l, ParsedPacket& out) noexcept {
    if (!l) return;
    try {
        TlsFields f;
        const uint8_t* data = l->getData();
        size_t         len  = l->getDataLen();
        if (len < 5) { return; }

        f.record_type   = data[0];
        f.major_version = data[1];
        f.minor_version = data[2];
        f.length        = (static_cast<uint16_t>(data[3]) << 8) | data[4];

        if      (f.major_version == 3 && f.minor_version == 1) f.tls_version_str = "TLS 1.0";
        else if (f.major_version == 3 && f.minor_version == 2) f.tls_version_str = "TLS 1.1";
        else if (f.major_version == 3 && f.minor_version == 3) f.tls_version_str = "TLS 1.2";
        else if (f.major_version == 3 && f.minor_version == 4) f.tls_version_str = "TLS 1.3";

        // Handshake record
        if (f.record_type == 22 && len >= 6) {
            f.handshake_type = data[5];

            // ClientHello: parse extensions for SNI, ALPN, supported_versions
            // Use a lambda to allow early returns without goto crossing declarations
            if (f.handshake_type == 1 && len > 43) {
                [&]() {
                    size_t off = 9; // record(5) + handshake_type(1) + length(3)
                    off += 2 + 32; // client_version(2) + random(32)
                    if (off >= len) return;
                    off += 1 + data[off]; // session_id
                    if (off + 2 > len) return;
                    uint16_t cs_len = (static_cast<uint16_t>(data[off]) << 8) | data[off+1];
                    off += 2 + cs_len; // cipher_suites
                    if (off >= len) return;
                    off += 1 + data[off]; // compression_methods
                    if (off + 2 > len) return;
                    uint16_t ext_total = (static_cast<uint16_t>(data[off]) << 8) | data[off+1];
                    off += 2;
                    size_t ext_end = std::min(off + ext_total, len);

                    while (off + 4 <= ext_end) {
                        uint16_t ext_type = (static_cast<uint16_t>(data[off])   << 8) | data[off+1];
                        uint16_t ext_len  = (static_cast<uint16_t>(data[off+2]) << 8) | data[off+3];
                        off += 4;
                        if (off + ext_len > ext_end) break;
                        if      (ext_type == 0x0000) parse_tls_sni(data+off, ext_len, f);
                        else if (ext_type == 0x0010) parse_tls_alpn(data+off, ext_len, f);
                        else if (ext_type == 0x002B) parse_tls_supported_versions(data+off, ext_len, f);
                        off += ext_len;
                    }
                }();
            }
        }
        // Alert record
        if (f.record_type == 21 && len >= 7) {
            f.alert_level       = data[5];
            f.alert_description = data[6];
        }
        out.tls = std::move(f);
    } catch (...) {}
}

// ── Flow key + protocol classification ───────────────────────────────────────

void DissectorEngine::build_flow_key(ParsedPacket& out) noexcept {
    auto& fk = out.flow_key;
    if (out.ip4) {
        fk.src_ip   = out.ip4->src_ip_str;
        fk.dst_ip   = out.ip4->dst_ip_str;
        fk.protocol = out.ip4->protocol;
        fk.valid    = true;
    } else if (out.ip6) {
        fk.src_ip   = out.ip6->src_ip_str;
        fk.dst_ip   = out.ip6->dst_ip_str;
        fk.protocol = out.ip6->next_header;
        fk.valid    = true;
    }
    if (out.tcp) { fk.src_port = out.tcp->src_port; fk.dst_port = out.tcp->dst_port; }
    else if (out.udp) { fk.src_port = out.udp->src_port; fk.dst_port = out.udp->dst_port; }
}

void DissectorEngine::classify_app_protocol(ParsedPacket& out) noexcept {
    // TLS ALPN takes highest priority (most specific)
    if (out.tls) {
        if (out.tls->alpn == "h2")          { out.app_protocol = AppProtocol::HTTP2;   return; }
        if (out.tls->alpn == "h3")          { out.app_protocol = AppProtocol::HTTP3;   return; }
        if (out.tls->alpn == "http/1.1")    { out.app_protocol = AppProtocol::HTTPS;   return; }
        out.app_protocol = AppProtocol::HTTPS;
        return;
    }
    if (out.dns)  { out.app_protocol = AppProtocol::DNS;  return; }
    if (out.http) { out.app_protocol = AppProtocol::HTTP; return; }
    if (out.arp)  { out.app_protocol = AppProtocol::ARP;  return; }
    if (out.icmp) { out.app_protocol = AppProtocol::ICMP; return; }
    if (out.icmpv6) { out.app_protocol = AppProtocol::ICMPv6; return; }

    // Port heuristics as fallback
    auto check = [](uint16_t p) -> AppProtocol {
        switch (p) {
            case 80: case 8080: case 8000:   return AppProtocol::HTTP;
            case 443: case 8443:             return AppProtocol::HTTPS;
            case 53:                         return AppProtocol::DNS;
            case 853:                        return AppProtocol::DNS_TLS;
            case 22:                         return AppProtocol::SSH;
            case 21:                         return AppProtocol::FTP;
            case 25: case 587: case 465:     return AppProtocol::SMTP;
            case 143: case 993:              return AppProtocol::IMAP;
            case 110: case 995:              return AppProtocol::POP3;
            case 5432:                       return AppProtocol::Postgres;
            case 3306:                       return AppProtocol::MySQL;
            case 6379:                       return AppProtocol::Redis;
            case 27017:                      return AppProtocol::MongoDB;
            case 1883: case 8883:            return AppProtocol::MQTT;
            default:                         return AppProtocol::Unknown;
        }
    };

    if (out.tcp) {
        auto p = check(out.tcp->dst_port);
        if (p == AppProtocol::Unknown) p = check(out.tcp->src_port);
        out.app_protocol = p;
    } else if (out.udp) {
        auto p = check(out.udp->dst_port);
        if (p == AppProtocol::Unknown) p = check(out.udp->src_port);
        out.app_protocol = p;
    }
}
