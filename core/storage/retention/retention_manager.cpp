#include "retention_manager.hpp"
#include <filesystem>
#include <iostream>
#include <chrono>
#include <algorithm>

namespace fs = std::filesystem;

namespace storage {

RetentionManager::RetentionManager(const std::string& directory, size_t max_bytes)
    : directory_(directory), max_bytes_(max_bytes) {
    if (!fs::exists(directory_)) {
        fs::create_directories(directory_);
    }
}

RetentionManager::~RetentionManager() {
    stop();
}

void RetentionManager::start() {
    running_ = true;
    thread_ = std::thread(&RetentionManager::run, this);
}

void RetentionManager::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

void RetentionManager::run() {
    while (running_) {
        enforce_retention();
        // check every 5 minutes
        for (int i = 0; i < 300 && running_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void RetentionManager::enforce_retention() {
    try {
        std::vector<fs::directory_entry> pcap_files;
        size_t total_size = 0;

        for (const auto& entry : fs::directory_iterator(directory_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".pcap") {
                pcap_files.push_back(entry);
                total_size += entry.file_size();
            }
        }

        if (total_size <= max_bytes_) return;

        std::sort(pcap_files.begin(), pcap_files.end(),
                  [](const fs::directory_entry& a, const fs::directory_entry& b) {
                      return a.last_write_time() < b.last_write_time();
                  });

        // Leave at least 1 file alone (the active one)
        for (size_t i = 0; i < pcap_files.size() - 1 && total_size > max_bytes_; ++i) {
            const auto& file = pcap_files[i];
            size_t size = file.file_size();
            std::cout << "[RetentionManager] Deleting old PCAP: " << file.path() << " (" << size << " bytes)\n";
            fs::remove(file.path());
            total_size -= size;
        }

    } catch (const std::exception& e) {
        std::cerr << "[RetentionManager] Error enforcing retention: " << e.what() << "\n";
    }
}

} // namespace storage
