#include "pcap_file_manager.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <filesystem>

namespace storage {

PcapFileManager::PcapFileManager(const std::string& output_dir)
    : output_dir_(output_dir) {
    if (!std::filesystem::exists(output_dir_)) {
        std::filesystem::create_directories(output_dir_);
    }
}

PcapFileManager::~PcapFileManager() {
    stop();
}

void PcapFileManager::start() {
    running_ = true;
    rotate_file();
    rotate_thread_ = std::thread(&PcapFileManager::rotate_thread_func, this);
}

void PcapFileManager::stop() {
    running_ = false;
    if (rotate_thread_.joinable()) {
        rotate_thread_.join();
    }
    std::lock_guard<std::mutex> lk(writer_mtx_);
    if (writer_) {
        writer_->close();
        writer_.reset();
    }
}

void PcapFileManager::write_packet(pcpp::RawPacket* packet) {
    std::lock_guard<std::mutex> lk(writer_mtx_);
    if (writer_) {
        // Metadata only capture: truncate to 96 bytes (snaplen)
        if (packet->getRawDataLen() > 96) {
            timespec ts = packet->getPacketTimeStamp();
            pcpp::RawPacket sliced(packet->getRawData(), 96, ts, false);
            writer_->writePacket(sliced);
        } else {
            writer_->writePacket(*packet);
        }
    }
}

void PcapFileManager::rotate_thread_func() {
    while (running_) {
        // Rotate every 10 minutes (600 seconds)
        for (int i = 0; i < 600 && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (running_) {
            rotate_file();
        }
    }
}

void PcapFileManager::rotate_file() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << output_dir_ << "/capture_" << std::put_time(std::localtime(&in_time_t), "%Y%m%d_%H%M%S") << ".pcap";
    
    std::lock_guard<std::mutex> lk(writer_mtx_);
    if (writer_) {
        writer_->close();
    }
    current_filename_ = ss.str();
    writer_ = std::make_unique<pcpp::PcapFileWriterDevice>(current_filename_);
    if (!writer_->open()) {
        std::cerr << "[PcapFileManager] Failed to open " << current_filename_ << "\n";
        writer_.reset();
    } else {
        std::cout << "[PcapFileManager] Rotating to new file: " << current_filename_ << "\n";
    }
}

} // namespace storage
