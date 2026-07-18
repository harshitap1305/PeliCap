#include "search_executor.hpp"
#include <iostream>

namespace search {
namespace executor {

SearchExecutor::SearchExecutor(PgConnectionPool& pool)
    : pool_(pool) {}

nlohmann::json SearchExecutor::execute(const planner::SqlPlan& plan) {
    nlohmann::json result;
    result["query"] = plan.sql;
    
    nlohmann::json results = nlohmann::json::array();
    
    try {
        auto conn_proxy = pool_.acquire();
        pqxx::work tx(*conn_proxy);
        
        pqxx::params p;
        for (const auto& param : plan.params) {
            p.append(param);
        }
        
        auto start_time = std::chrono::steady_clock::now();
        pqxx::result r = tx.exec(plan.sql, p);
        auto end_time = std::chrono::steady_clock::now();
        
        result["latency_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        result["count"] = r.size();
        
        for (const auto& row : r) {
            nlohmann::json j;
            j["flow_id"] = row["flow_id"].as<uint64_t>();
            
            // Just basic metadata to show in search results
            if (!row["src_ip"].is_null()) j["src_ip"] = row["src_ip"].c_str();
            if (!row["dst_ip"].is_null()) j["dst_ip"] = row["dst_ip"].c_str();
            if (!row["src_port"].is_null()) j["src_port"] = row["src_port"].as<int>();
            if (!row["dst_port"].is_null()) j["dst_port"] = row["dst_port"].as<int>();
            if (!row["protocol"].is_null()) j["protocol"] = row["protocol"].as<int>();
            
            if (!row["duration_ms"].is_null()) j["duration_ms"] = row["duration_ms"].as<int>();
            if (!row["payload_bytes"].is_null()) j["payload_bytes"] = row["payload_bytes"].as<uint64_t>();
            
            if (!row["app_protocol"].is_null()) j["app_protocol"] = row["app_protocol"].as<int>();
            if (!row["tls_sni"].is_null()) j["tls_sni"] = row["tls_sni"].c_str();
            if (!row["http_host"].is_null()) j["http_host"] = row["http_host"].c_str();
            if (!row["dns_query"].is_null()) j["dns_query"] = row["dns_query"].c_str();
            if (!row["session_id"].is_null()) j["session_id"] = row["session_id"].c_str();
            
            results.push_back(j);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[SearchExecutor] query failed: " << e.what() << "\n";
        result["error"] = e.what();
    }
    
    result["results"] = results;
    return result;
}

} // namespace executor
} // namespace search
