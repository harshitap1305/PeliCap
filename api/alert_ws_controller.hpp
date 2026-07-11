#pragma once
#include <drogon/WebSocketController.h>
#include "../core/detection/alert.hpp"
#include <vector>
#include <mutex>
#include <string>

// ── AlertWsController ─────────────────────────────────────────────────────────
// Drogon WebSocket controller at /ws/alerts.
// Connected clients receive every new alert as JSON in real-time.
// The DetectionEngine calls AlertWsController::broadcast() via the
// AlertStore persistence callback (after the alert is pushed to the store).
//
// Thread-safety: clients_ vector is protected by ws_mtx_.
// Drogon invokes handleNewConnection / handleConnectionClosed on I/O threads.
// broadcast() may be called from the DetectionEngine tick thread — safe via mutex.

class AlertWsController
    : public drogon::WebSocketController<AlertWsController> {
public:
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/alerts");
    WS_PATH_LIST_END

    void handleNewConnection(
        const drogon::HttpRequestPtr& req,
        const drogon::WebSocketConnectionPtr& conn) override
    {
        std::lock_guard<std::mutex> lk(ws_mtx_);
        clients_.push_back(conn);
        // Greet with current alert count
        nlohmann::json hello = {{"type", "connected"},
                                 {"message", "PaliCap alert stream connected"}};
        conn->send(hello.dump());
    }

    void handleConnectionClosed(
        const drogon::WebSocketConnectionPtr& conn) override
    {
        std::lock_guard<std::mutex> lk(ws_mtx_);
        clients_.erase(
            std::remove_if(clients_.begin(), clients_.end(),
                           [&](const auto& c) { return c == conn; }),
            clients_.end());
    }

    void handleNewMessage(
        const drogon::WebSocketConnectionPtr& conn,
        std::string&& msg,
        const drogon::WebSocketMessageType& type) override
    {
        // Clients can send {"type":"ping"} — we echo {"type":"pong"}
        if (type == drogon::WebSocketMessageType::Text) {
            try {
                auto j = nlohmann::json::parse(msg);
                if (j.value("type", "") == "ping")
                    conn->send(nlohmann::json{{"type","pong"}}.dump());
            } catch (...) {}
        }
    }

    // Called by AlertStore callback — pushes alert JSON to all connected clients
    static void broadcast(const Alert& a) {
        std::lock_guard<std::mutex> lk(ws_mtx_);
        if (clients_.empty()) return;
        std::string payload = a.to_json().dump();
        for (auto& c : clients_) {
            if (c && c->connected())
                c->send(payload);
        }
    }

private:
    inline static std::mutex ws_mtx_;
    inline static std::vector<drogon::WebSocketConnectionPtr> clients_;
};
