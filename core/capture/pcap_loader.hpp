#pragma once
#include "capture/packet.hpp"
#include "dispatch/packet_bus.hpp"
#include <PcapFileDevice.h>
#include <string>
#include <memory>

class PcapLoader {
public:
    PcapLoader(std::string filepath, PacketBus& bus);
    ~PcapLoader();

    void load_all();
    
    uint64_t packets_loaded() const { return packets_loaded_; }

private:
    std::string filepath_;
    PacketBus& bus_;
    uint64_t packets_loaded_ = 0;
};
