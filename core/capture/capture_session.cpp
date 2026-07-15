#include "capture_session.hpp"
#include <PcapLiveDeviceList.h>
#include <stdexcept>
#include <iostream>
#include <random>
#include <sstream>
#include <iomanip>

static std::string generate_uuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 8; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 4; i++) ss << dis(gen);
    ss << "-4";
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    ss << dis2(gen);
    for (int i = 0; i < 3; i++) ss << dis(gen);
    ss << "-";
    for (int i = 0; i < 12; i++) ss << dis(gen);
    return ss.str();
}

CaptureSession::CaptureSession(Config cfg, PacketBus& bus)
    : config_(std::move(cfg)), bus_(bus), session_id_(generate_uuid()) {
}

CaptureSession::~CaptureSession() {
    stop();
}

void CaptureSession::start() {
    device_ = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(config_.interface_name);
    if (!device_) {
        throw std::runtime_error("Cannot find interface: " + config_.interface_name);
    }

    pcpp::PcapLiveDevice::DeviceConfiguration devConfig(
        config_.promiscuous ? pcpp::PcapLiveDevice::Promiscuous : pcpp::PcapLiveDevice::Normal
    );
    if (!device_->open(devConfig)) {
        throw std::runtime_error("Cannot open interface: " + config_.interface_name);
    }

    if (!config_.bpf_filter.empty()) {
        if (!device_->setFilter(config_.bpf_filter)) {
            throw std::runtime_error("Invalid BPF filter: " + config_.bpf_filter);
        }
    }

    if (!device_->startCapture(onPacketArrives, this)) {
        throw std::runtime_error("Failed to start capture on: " + config_.interface_name);
    }
}

void CaptureSession::stop() {
    if (device_ && device_->isOpened()) {
        device_->stopCapture();
        device_->close();
    }
    device_ = nullptr;
}

void CaptureSession::onPacketArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie) {
    auto* self = static_cast<CaptureSession*>(cookie);

    CapturedPacket* pkt = new CapturedPacket();
    pkt->id = ++self->packets_captured_;
    
    timespec ts = rawPacket->getPacketTimeStamp();
    pkt->timestamp = std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
    
    pkt->captured_len = rawPacket->getRawDataLen();
    pkt->original_len = rawPacket->getRawDataLen();
    pkt->raw.assign(rawPacket->getRawData(), rawPacket->getRawData() + pkt->captured_len);
    pkt->interface_name = self->config_.interface_name;
    pkt->session_id = self->session_id_;
    pkt->link_type = rawPacket->getLinkLayerType();

    if (!self->bus_.publish(pkt)) {
        self->packets_dropped_++;
    }
}
