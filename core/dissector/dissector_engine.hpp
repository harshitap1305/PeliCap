#pragma once

#include "parsed_packet.hpp"
#include "../capture/packet.hpp"

// PcapPlusPlus layer headers
#include <Packet.h>
#include <EthLayer.h>
#include <VlanLayer.h>
#include <ArpLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <IcmpLayer.h>
#include <IcmpV6Layer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <DnsLayer.h>
#include <HttpLayer.h>
#include <SSLLayer.h>

class DissectorEngine {
public:
    // Main entry point — stateless, thread-safe, never throws
    static ParsedPacket dissect(const CapturedPacket& raw) noexcept;

private:
    // Layer parsers — all noexcept, all guard against null input
    static void parse_ethernet(pcpp::EthLayer*,          ParsedPacket&) noexcept;
    static void parse_vlan    (pcpp::VlanLayer*,         ParsedPacket&) noexcept;
    static void parse_arp     (pcpp::ArpLayer*,          ParsedPacket&) noexcept;
    static void parse_ipv4    (pcpp::IPv4Layer*,         ParsedPacket&) noexcept;
    static void parse_ipv6    (pcpp::IPv6Layer*,         ParsedPacket&) noexcept;
    static void parse_icmp    (pcpp::IcmpLayer*,         ParsedPacket&) noexcept;
    static void parse_icmpv6  (pcpp::IcmpV6Layer*,       ParsedPacket&) noexcept;
    static void parse_tcp     (pcpp::TcpLayer*,          ParsedPacket&) noexcept;
    static void parse_udp     (pcpp::UdpLayer*,          ParsedPacket&) noexcept;
    static void parse_dns     (pcpp::DnsLayer*,          ParsedPacket&) noexcept;
    static void parse_http_req(pcpp::HttpRequestLayer*,  ParsedPacket&) noexcept;
    static void parse_http_res(pcpp::HttpResponseLayer*, ParsedPacket&) noexcept;
    static void parse_tls     (pcpp::SSLLayer*,          ParsedPacket&) noexcept;

    // Post-parse steps
    static void build_flow_key         (ParsedPacket&) noexcept;
    static void classify_app_protocol  (ParsedPacket&) noexcept;

    // Helpers
    static std::string mac_to_string(const pcpp::MacAddress&) noexcept;

    // TLS extension parsers (called from parse_tls)
    static void parse_tls_sni         (const uint8_t* ext_data, uint16_t ext_len, TlsFields&) noexcept;
    static void parse_tls_alpn        (const uint8_t* ext_data, uint16_t ext_len, TlsFields&) noexcept;
    static void parse_tls_supported_versions(const uint8_t* ext_data, uint16_t ext_len, TlsFields&) noexcept;
};
