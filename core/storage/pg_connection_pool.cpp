#include "pg_connection_pool.hpp"

PgConnectionPool::PgConnectionPool(const std::string& dsn, size_t pool_size)
    : dsn_(dsn), pool_size_(pool_size) {
    for (size_t i = 0; i < pool_size_; ++i) {
        try {
            connections_.push_back(std::make_unique<pqxx::connection>(dsn_));
        } catch (const std::exception& e) {
            std::cerr << "[PgConnectionPool] Failed to create connection on init: " << e.what() << "\n";
            connections_.push_back(nullptr);
        }
    }
}

PgConnectionPool::~PgConnectionPool() {
    std::lock_guard<std::mutex> lk(mtx_);
    connections_.clear();
}

PgConnectionPool::ConnectionProxy PgConnectionPool::acquire() {
    std::unique_lock<std::mutex> lk(mtx_);
    cv_.wait(lk, [this]() { return !connections_.empty(); });

    auto conn = std::move(connections_.back());
    connections_.pop_back();
    lk.unlock();

    if (!conn || !conn->is_open()) {
        try {
            conn = std::make_unique<pqxx::connection>(dsn_);
        } catch (const std::exception& e) {
            std::cerr << "[PgConnectionPool] Reconnect failed: " << e.what() << "\n";
            release(nullptr);
            throw; 
        }
    }

    return ConnectionProxy(this, std::move(conn));
}

void PgConnectionPool::release(std::unique_ptr<pqxx::connection> conn) {
    std::lock_guard<std::mutex> lk(mtx_);
    connections_.push_back(std::move(conn));
    cv_.notify_one();
}
