#pragma once
#include <pqxx/pqxx>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <string>
#include <iostream>

class PgConnectionPool {
public:
    PgConnectionPool(const std::string& dsn, size_t pool_size = 8);
    ~PgConnectionPool();

    class ConnectionProxy {
    public:
        ConnectionProxy(PgConnectionPool* pool, std::unique_ptr<pqxx::connection> conn)
            : pool_(pool), conn_(std::move(conn)) {}
        
        ~ConnectionProxy() {
            if (pool_ && conn_) {
                pool_->release(std::move(conn_));
            }
        }
        
        ConnectionProxy(const ConnectionProxy&) = delete;
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;
        
        ConnectionProxy(ConnectionProxy&& other) noexcept 
            : pool_(other.pool_), conn_(std::move(other.conn_)) {
            other.pool_ = nullptr;
        }

        pqxx::connection& operator*() { return *conn_; }
        pqxx::connection* operator->() { return conn_.get(); }

    private:
        PgConnectionPool* pool_;
        std::unique_ptr<pqxx::connection> conn_;
    };

    ConnectionProxy acquire();

private:
    void release(std::unique_ptr<pqxx::connection> conn);

    std::string dsn_;
    size_t pool_size_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::vector<std::unique_ptr<pqxx::connection>> connections_;
};
