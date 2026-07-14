#pragma once
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>

namespace storage {

class PcapFileManager {
public:
    explicit PcapFileManager(const std::string& output_dir);
    ~PcapFileManager();

    void start();
    void stop();

    void write_packet(pcpp::RawPacket* packet);

private:
    void rotate_thread_func();
    void rotate_file();

    std::string output_dir_;
    std::mutex writer_mtx_;
    std::unique_ptr<pcpp::PcapFileWriterDevice> writer_;
    
    std::thread rotate_thread_;
    std::atomic<bool> running_{false};
    std::string current_filename_;
};

} // namespace storage
