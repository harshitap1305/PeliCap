#pragma once
#include "alert.hpp"
#include <libpq-fe.h>
#include <string>
#include <atomic>
#include <iostream>
#include <sstream>

// ── PgStore ───────────────────────────────────────────────────────────────────
// Thin wrapper around libpq (PostgreSQL C client).
// Inserts Alert records asynchronously — uses a synchronous PQexecParams call
// on the alert callback thread. Falls back gracefully if PG is unavailable.
// The in-memory AlertStore ring buffer is always the primary query path;
// PostgreSQL is purely for long-term persistence and audit.

class PgStore {
public:
    PgStore() = default;
    ~PgStore() { disconnect(); }

    // Returns true if connected successfully
    bool connect(const std::string& dsn) {
        conn_ = PQconnectdb(dsn.c_str());
        if (PQstatus(conn_) != CONNECTION_OK) {
            std::cerr << "[PgStore] Connection failed: "
                      << PQerrorMessage(conn_) << "\n";
            PQfinish(conn_);
            conn_ = nullptr;
            return false;
        }
        std::cout << "[PgStore] Connected to PostgreSQL\n";
        connected_ = true;
        return true;
    }

    void disconnect() {
        if (conn_) { PQfinish(conn_); conn_ = nullptr; }
        connected_ = false;
    }

    bool is_connected() const { return connected_; }

    bool insert_alert(const Alert& a) {
        if (!conn_ || !connected_) return false;
        if (a.session_id.empty()) return false; // Ignore alerts without session_id

        // Check connection is still alive, reconnect if needed
        if (PQstatus(conn_) != CONNECTION_OK) {
            PQreset(conn_);
            if (PQstatus(conn_) != CONNECTION_OK) {
                connected_ = false;
                return false;
            }
        }

        const char* sql =
            "INSERT INTO alerts "
            "(alert_id, type, severity, timestamp_ns, title, description, "
            " src_ip, dst_ip, domain, endpoint, observed_value, threshold_value, "
            " baseline_value, correlation_id, is_ongoing, session_id) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) "
            "ON CONFLICT (alert_id) DO NOTHING";

        std::string alert_id_s   = std::to_string(a.alert_id);
        std::string type_s       = std::to_string(static_cast<int>(a.type));
        std::string severity_s   = std::to_string(static_cast<int>(a.severity));
        std::string ts_s         = std::to_string(a.timestamp_ns);
        std::string obs_s        = std::to_string(a.context.observed_value);
        std::string thr_s        = std::to_string(a.context.threshold_value);
        std::string base_s       = std::to_string(a.context.baseline_value);
        std::string corr_s       = std::to_string(a.correlation_id);
        std::string ongoing_s    = a.is_ongoing ? "true" : "false";

        const char* params[16] = {
            alert_id_s.c_str(),
            type_s.c_str(),
            severity_s.c_str(),
            ts_s.c_str(),
            a.title.c_str(),
            a.description.c_str(),
            a.context.src_ip.empty()   ? nullptr : a.context.src_ip.c_str(),
            a.context.dst_ip.empty()   ? nullptr : a.context.dst_ip.c_str(),
            a.context.domain.empty()   ? nullptr : a.context.domain.c_str(),
            a.context.endpoint.empty() ? nullptr : a.context.endpoint.c_str(),
            obs_s.c_str(),
            thr_s.c_str(),
            base_s.c_str(),
            corr_s.c_str(),
            ongoing_s.c_str(),
            a.session_id.c_str()
        };

        PGresult* res = PQexecParams(conn_, sql, 16,
                                     nullptr, params, nullptr, nullptr, 0);

        bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
        if (!ok) {
            std::cerr << "[PgStore] Insert failed: " << PQerrorMessage(conn_) << "\n";
        }
        PQclear(res);
        return ok;
    }

private:
    PGconn* conn_      = nullptr;
    bool    connected_ = false;
};
