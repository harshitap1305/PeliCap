#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include "../dissector/parsed_packet.hpp"

// ── FlowKey ──────────────────────────────────────────────────────────────────
// 40-byte struct — uniform layout for IPv4 and IPv6.
// IPv4 addresses are stored as 4 bytes followed by 12 zero bytes.
// ICMP/ICMPv6: src_port = echo-id, dst_port = 0.
// Always normalized so the lower (addr,port) tuple is in src_addr/src_port.

struct FlowKey {
    uint8_t  src_addr[16] = {};
    uint8_t  dst_addr[16] = {};
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;
    uint8_t  protocol     = 0;  // IPPROTO_TCP=6, UDP=17, ICMP=1, ICMPv6=58
    uint8_t  is_ipv6      = 0;
    uint8_t  _pad[2]      = {};  // explicit padding → 40 bytes, no UB

    // ── Factory ──────────────────────────────────────────────────────────────
    static std::optional<FlowKey> from_packet(const ParsedPacket& pkt) noexcept {
        FlowKey k;

        // ── L3: fill addresses ────────────────────────────────────────────
        if (pkt.ip4) {
            k.is_ipv6 = 0;
            // Store IPv4 as 4 bytes, rest zero
            uint32_t s = pkt.ip4->src_ip;
            uint32_t d = pkt.ip4->dst_ip;
            std::memcpy(k.src_addr, &s, 4);
            std::memcpy(k.dst_addr, &d, 4);
            k.protocol = pkt.ip4->protocol;
        } else if (pkt.ip6) {
            k.is_ipv6 = 1;
            std::memcpy(k.src_addr, pkt.ip6->src_ip_raw.data(), 16);
            std::memcpy(k.dst_addr, pkt.ip6->dst_ip_raw.data(), 16);
            k.protocol = pkt.ip6->next_header;
        } else if (pkt.arp) {
            // ARP — not a routable flow, skip
            return std::nullopt;
        } else {
            return std::nullopt;
        }

        // ── L4: fill ports (or ICMP surrogate) ───────────────────────────
        if (pkt.tcp) {
            k.src_port = pkt.tcp->src_port;
            k.dst_port = pkt.tcp->dst_port;
        } else if (pkt.udp) {
            k.src_port = pkt.udp->src_port;
            k.dst_port = pkt.udp->dst_port;
        } else if (pkt.icmp) {
            // ICMP echo: use id as surrogate src_port, 0 as dst
            // This groups echo-request and echo-reply into the same flow
            k.src_port = pkt.icmp->id;
            k.dst_port = 0;
        } else if (pkt.icmpv6) {
            k.src_port = pkt.icmpv6->id;
            k.dst_port = 0;
        }
        // Else: protocol with no port (e.g. raw IGMP) — use ports=0, still trackable

        // ── Bidirectional normalization ───────────────────────────────────
        // Always store the "smaller" endpoint as src so A→B and B→A share a key.
        int addr_cmp = std::memcmp(k.src_addr, k.dst_addr, 16);
        bool swap = (addr_cmp > 0) || (addr_cmp == 0 && k.src_port > k.dst_port);
        if (swap) {
            uint8_t tmp[16];
            std::memcpy(tmp,         k.src_addr, 16);
            std::memcpy(k.src_addr,  k.dst_addr, 16);
            std::memcpy(k.dst_addr,  tmp,         16);
            std::swap(k.src_port, k.dst_port);
        }

        return k;
    }

    bool operator==(const FlowKey& o) const noexcept {
        return std::memcmp(this, &o, sizeof(FlowKey)) == 0;
    }
};

// ── FlowKeyHash ───────────────────────────────────────────────────────────────
// Multiply-mix hash on all 40 bytes.  Fast, good avalanche, no dependencies.
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        // XOR-fold 40 bytes into 8 bytes using 5×uint64 reads
        uint64_t h[5] = {};
        static_assert(sizeof(k) == 40, "FlowKey must be 40 bytes");
        std::memcpy(h, &k, 40);

        uint64_t acc = h[0];
        for (int i = 1; i < 5; ++i) {
            acc ^= h[i];
            acc ^= acc >> 33;
            acc *= 0xff51afd7ed558ccdULL;
            acc ^= acc >> 33;
            acc *= 0xc4ceb9fe1a85ec53ULL;
            acc ^= acc >> 33;
        }
        return static_cast<size_t>(acc);
    }
};
