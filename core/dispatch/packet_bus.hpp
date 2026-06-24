#pragma once

#include "capture/packet.hpp"
#include <boost/lockfree/spsc_queue.hpp>
#include <functional>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>

class PacketBus {
public:
    using PacketCallback = std::function<void(const CapturedPacket&)>;

    PacketBus() : running_(false) {}

    ~PacketBus() {
        stop();
    }

    void start() {
        if (running_) return;
        running_ = true;
        dispatch_thread_ = std::thread([this]() { run_loop(); });
    }

    void stop() {
        running_ = false;
        if (dispatch_thread_.joinable()) {
            dispatch_thread_.join();
        }
        
        // Clear remaining packets
        CapturedPacket* pkt = nullptr;
        while (queue_.pop(pkt)) {
            delete pkt;
        }
    }

    // Fast-path for capture thread
    bool publish(CapturedPacket* pkt, bool drop_on_full = true) {
        if (!queue_.push(pkt)) {
            // Queue full - packet dropped
            if (drop_on_full) {
                delete pkt;
            }
            return false;
        }
        return true;
    }

    // Must be called before start() to avoid race conditions
    void subscribe(PacketCallback cb) {
        subscribers_.push_back(std::move(cb));
    }

private:
    void run_loop() {
        CapturedPacket* pkt = nullptr;
        while (running_) {
            if (queue_.pop(pkt)) {
                for (const auto& sub : subscribers_) {
                    sub(*pkt);
                }
                delete pkt;
            } else {
                // Yield to prevent 100% CPU usage when idle
                std::this_thread::yield();
            }
        }
        
        // Process remaining queue before exiting thread
        while (queue_.pop(pkt)) {
            for (const auto& sub : subscribers_) {
                sub(*pkt);
            }
            delete pkt;
        }
    }

    // 1M packet capacity ring buffer
    boost::lockfree::spsc_queue<CapturedPacket*, boost::lockfree::capacity<1000000>> queue_;
    std::vector<PacketCallback> subscribers_;
    std::atomic<bool> running_;
    std::thread dispatch_thread_;
};
