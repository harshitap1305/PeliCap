#pragma once

#include <cstdint>
#include <vector>
#include <chrono>
#include <string>
#include <array>
#include <memory>

struct CapturedPacket {
    // Identity
    uint64_t id;
    std::chrono::nanoseconds timestamp;
    
    // Raw bytes — the full frame exactly as captured
    std::vector<uint8_t> raw;
    uint32_t captured_len;
    uint32_t original_len;
    
    // Capture context
    std::string interface_name;
    std::string session_id;
    int link_type;
    
    struct Parsed {
        // Ethernet
        std::array<uint8_t, 6> src_mac{};
        std::array<uint8_t, 6> dst_mac{};
        uint16_t ethertype = 0;
        
        // IP
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        uint8_t  protocol = 0;
        uint8_t  ttl = 0;
        uint16_t ip_length = 0;
        
        // Transport
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        
        // TCP-specific
        uint32_t seq = 0;
        uint32_t ack = 0;
        uint8_t  tcp_flags = 0;
        uint16_t window_size = 0;
        
        // State
        bool is_parsed = false;
    } parsed;
};
