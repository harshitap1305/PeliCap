#pragma once
#include "capture/packet.hpp"
#include "dispatch/packet_bus.hpp"
#include <PcapLiveDevice.h>
#include <string>
#include <memory>
#include <atomic>

class CaptureSession {
public:
    struct Config {
        std::string interface_name;
        std::string bpf_filter;
        bool promiscuous = true;
    };

    CaptureSession(Config cfg, PacketBus& bus);
    ~CaptureSession();

    void start();
    void stop();

    uint64_t packets_captured() const { return packets_captured_.load(); }
    uint64_t packets_dropped() const { return packets_dropped_.load(); }
    const std::string& get_session_id() const { return session_id_; }

private:
    std::string session_id_;
    static void onPacketArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie);

    Config config_;
    PacketBus& bus_;
    pcpp::PcapLiveDevice* device_ = nullptr;
    std::atomic<uint64_t> packets_captured_{0};
    std::atomic<uint64_t> packets_dropped_{0};
};
