#include "batch_writer.hpp"
#include "../flow/flow.hpp"
#include "../detection/alert.hpp"
#include <chrono>
#include <iostream>
#include <sstream>

namespace storage {

// Helper: reclaim shared_ptr ownership from raw block pointer and cast to T.
template<typename T>
static std::shared_ptr<T> reclaim(void* shared_block) {
    auto* heap = static_cast<std::shared_ptr<T>*>(shared_block);
    std::shared_ptr<T> result = std::move(*heap);
    delete heap;
    return result;
}

BatchWriter::BatchWriter(WriteQueue& queue, PgConnectionPool& pool)
    : queue_(queue), pool_(pool) {}

BatchWriter::~BatchWriter() {
    stop();
}

void BatchWriter::start() {
    running_ = true;
    thread_ = std::thread(&BatchWriter::run, this);
}

void BatchWriter::stop() {
    running_ = false;
    if (thread_.joinable()) {
        thread_.join();
    }
}

void BatchWriter::run() {
    std::vector<StorageEvent> batch;
    batch.reserve(1000);

    while (running_) {
        StorageEvent event;
        while (queue_.pop(event)) {
            batch.push_back(event);
            if (batch.size() >= 1000) break;
        }

        if (!batch.empty()) {
            flush_batch(batch);
            batch.clear();
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    // Final drain on shutdown
    StorageEvent event;
    while (queue_.pop(event)) batch.push_back(event);
    if (!batch.empty()) flush_batch(batch);
}

void BatchWriter::flush_batch(std::vector<StorageEvent>& batch) {
    std::vector<StorageEvent> flows, alerts, others;
    for (auto& ev : batch) {
        switch (ev.type) {
            case EventType::FLOW_CLOSED:  flows.push_back(ev);  break;
            case EventType::ALERT_FIRED:  alerts.push_back(ev); break;
            default:
                // Free ownership for types we don't handle yet
                if (ev.shared_block) {
                    auto* heap = static_cast<std::shared_ptr<void>*>(ev.shared_block);
                    delete heap;
                }
                break;
        }
    }

    try {
        auto conn_proxy = pool_.acquire();
        pqxx::work tx(*conn_proxy);
        if (!flows.empty())  insert_flows(tx, flows);
        if (!alerts.empty()) insert_alerts(tx, alerts);
        tx.commit();
    } catch (const std::exception& e) {
        std::cerr << "[BatchWriter] flush_batch failed: " << e.what() << "\n";
        // Even on failure we must free the heap-allocated shared_ptrs
        for (auto& ev : flows)  if (ev.shared_block) { delete static_cast<std::shared_ptr<Flow>*>(ev.shared_block); }
        for (auto& ev : alerts) if (ev.shared_block) { delete static_cast<std::shared_ptr<Alert>*>(ev.shared_block); }
    }
}

void BatchWriter::insert_flows(pqxx::work& tx, const std::vector<StorageEvent>& events) {
    for (const auto& ev : events) {
        auto flow = reclaim<Flow>(ev.shared_block);
        if (!flow) continue;

        try {
            // Convert ns timestamps to microseconds for PostgreSQL TIMESTAMPTZ
            auto start_us = flow->start_time_ns / 1000;
            auto end_us   = flow->last_seen_ns  / 1000;
            auto dur_ms   = static_cast<int32_t>(flow->duration_ns() / 1'000'000);

            tx.exec(
                "INSERT INTO flows "
                "(flow_id, start_time, src_ip, dst_ip, src_port, dst_port, protocol, "
                " interface_name, end_time, duration_ms, fwd_packets, rev_packets, "
                " fwd_bytes, rev_bytes, payload_bytes, tcp_state, avg_rtt_us, min_rtt_us, "
                " retransmit_count, zero_window_events, app_protocol, tls_sni, http_host, dns_query) "
                "VALUES ($1, to_timestamp($2::bigint / 1000000.0), $3::inet, $4::inet, "
                "  $5, $6, $7, $8, to_timestamp($9::bigint / 1000000.0), $10, "
                "  $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24) "
                "ON CONFLICT DO NOTHING",
                pqxx::params{
                    (int64_t)flow->flow_id,
                    start_us,
                    flow->src_ip_str,
                    flow->dst_ip_str,
                    (int)flow->src_port,
                    (int)flow->dst_port,
                    (int)flow->protocol,
                    flow->interface_name,
                    end_us,
                    dur_ms,
                    (int64_t)flow->fwd_packets,
                    (int64_t)flow->rev_packets,
                    (int64_t)flow->fwd_bytes,
                    (int64_t)flow->rev_bytes,
                    (int64_t)flow->payload_bytes,
                    (int)static_cast<uint8_t>(flow->tcp_state),
                    (int)flow->rtt.avg(),
                    (int)flow->rtt.min(),
                    (int)flow->retransmit.count,
                    (int)flow->zero_window_events,
                    (int)static_cast<uint8_t>(flow->app_protocol),
                    flow->tls_sni,
                    flow->http_host,
                    flow->dns_query
                }
            );
        } catch (const std::exception& e) {
            std::cerr << "[BatchWriter] insert_flows row error: " << e.what() << "\n";
        }
    }
}

void BatchWriter::insert_alerts(pqxx::work& tx, const std::vector<StorageEvent>& events) {
    for (const auto& ev : events) {
        auto alert = reclaim<Alert>(ev.shared_block);
        if (!alert) continue;

        try {
            tx.exec(
                "INSERT INTO alerts "
                "(alert_id, type, severity, timestamp_ns, title, description, "
                " src_ip, dst_ip, domain, endpoint, observed_value, threshold_value, "
                " baseline_value, correlation_id, is_ongoing) "
                "VALUES ($1, $2, $3, $4, $5, $6, "
                "  $7::inet, $8::inet, $9, $10, $11, $12, $13, $14, $15) "
                "ON CONFLICT (alert_id) DO NOTHING",
                pqxx::params{
                    (int64_t)alert->alert_id,
                    (int)static_cast<uint16_t>(alert->type),
                    (int)static_cast<uint8_t>(alert->severity),
                    alert->timestamp_ns,
                    alert->title,
                    alert->description,
                    alert->context.src_ip.empty()   ? pqxx::zview{} : pqxx::zview{alert->context.src_ip},
                    alert->context.dst_ip.empty()   ? pqxx::zview{} : pqxx::zview{alert->context.dst_ip},
                    alert->context.domain,
                    alert->context.endpoint,
                    alert->context.observed_value,
                    alert->context.threshold_value,
                    alert->context.baseline_value,
                    (int64_t)alert->correlation_id,
                    alert->is_ongoing
                }
            );
        } catch (const std::exception& e) {
            std::cerr << "[BatchWriter] insert_alerts row error: " << e.what() << "\n";
        }
    }
}

} // namespace storage
