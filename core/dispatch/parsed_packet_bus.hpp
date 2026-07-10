#pragma once

#include "dissector/parsed_packet.hpp"
#include <boost/lockfree/spsc_queue.hpp>
#include <functional>
#include <vector>
#include <thread>
#include <atomic>

class ParsedPacketBus {
public:
    using Callback = std::function<void(const ParsedPacket&)>;

    ParsedPacketBus() : running_(false) {}
    ~ParsedPacketBus() { stop(); }

    void start() {
        if (running_) return;
        running_ = true;
        thread_ = std::thread([this]() { run_loop(); });
    }

    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        ParsedPacket* p = nullptr;
        while (queue_.pop(p)) delete p;
    }

    bool publish(ParsedPacket* p) {
        if (!queue_.push(p)) { delete p; return false; }
        return true;
    }

    void subscribe(Callback cb) {
        subscribers_.push_back(std::move(cb));
    }

private:
    void run_loop() {
        ParsedPacket* p = nullptr;
        while (running_) {
            if (queue_.pop(p)) {
                for (auto& cb : subscribers_) cb(*p);
                delete p;
            } else {
                std::this_thread::yield();
            }
        }
        while (queue_.pop(p)) {
            for (auto& cb : subscribers_) cb(*p);
            delete p;
        }
    }

    boost::lockfree::spsc_queue<ParsedPacket*, boost::lockfree::capacity<500000>> queue_;
    std::vector<Callback> subscribers_;
    std::atomic<bool> running_;
    std::thread thread_;
};
