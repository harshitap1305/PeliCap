#pragma once
#include "write_queue.hpp"
#include "pg_connection_pool.hpp"
#include <thread>
#include <atomic>
#include <vector>

namespace storage {

class BatchWriter {
public:
    BatchWriter(WriteQueue& queue, PgConnectionPool& pool);
    ~BatchWriter();

    void start();
    void stop();

private:
    void run();
    void flush_batch(std::vector<StorageEvent>& batch);
    
    void insert_flows(pqxx::work& tx, std::vector<StorageEvent>& events);
    void insert_alerts(pqxx::work& tx, std::vector<StorageEvent>& events);
    void insert_sessions(pqxx::work& tx, std::vector<StorageEvent>& events);

    WriteQueue& queue_;
    PgConnectionPool& pool_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace storage
