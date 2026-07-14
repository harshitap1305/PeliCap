#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <vector>

namespace storage {

class RetentionManager {
public:
    // Default max_bytes is 5 GB
    RetentionManager(const std::string& directory, size_t max_bytes = 5ULL * 1024 * 1024 * 1024);
    ~RetentionManager();

    void start();
    void stop();

private:
    void run();
    void enforce_retention();

    std::string directory_;
    size_t max_bytes_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace storage
