#include "pcap_loader.hpp"
#include <stdexcept>
#include <thread>
#include <chrono>

PcapLoader::PcapLoader(std::string filepath, PacketBus& bus)
    : filepath_(std::move(filepath)), bus_(bus) {
}

PcapLoader::~PcapLoader() = default;

void PcapLoader::load_all() {
    pcpp::PcapFileReaderDevice reader(filepath_);
    if (!reader.open()) {
        throw std::runtime_error("Cannot open PCAP file: " + filepath_);
    }

    pcpp::RawPacket rawPacket;
    while (reader.getNextPacket(rawPacket)) {
        CapturedPacket* pkt = new CapturedPacket();
        pkt->id = ++packets_loaded_;
        
        timespec ts = rawPacket.getPacketTimeStamp();
        pkt->timestamp = std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
        
        pkt->captured_len = rawPacket.getRawDataLen();
        pkt->original_len = rawPacket.getRawDataLen();
        pkt->raw.assign(rawPacket.getRawData(), rawPacket.getRawData() + pkt->captured_len);
        pkt->interface_name = "pcap_file";
        pkt->link_type = rawPacket.getLinkLayerType();

        while (!bus_.publish(pkt, false)) {
            // Queue is full, back off and retry instead of dropping
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    reader.close();
}
