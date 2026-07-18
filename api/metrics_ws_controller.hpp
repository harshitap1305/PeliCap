#pragma once
#include <drogon/WebSocketController.h>
#include <vector>
#include <mutex>
#include <string>
#include <json/json.h>

// ── MetricsWsController ───────────────────────────────────────────────────────
// Drogon WebSocket controller at /ws/metrics.
// Connected clients receive metrics summary JSON in real-time (e.g. every 1s).
// The MetricsEngine or CaptureApi calls MetricsWsController::broadcast() periodically.
//
// Thread-safety: clients_ vector is protected by ws_mtx_.

class MetricsWsController
    : public drogon::WebSocketController<MetricsWsController> {
public:
    WS_PATH_LIST_BEGIN
    WS_PATH_ADD("/ws/metrics");
    WS_PATH_LIST_END

    void handleNewConnection(
        const drogon::HttpRequestPtr& req,
        const drogon::WebSocketConnectionPtr& conn) override
    {
        std::lock_guard<std::mutex> lk(ws_mtx_);
        clients_.push_back(conn);
        Json::Value hello;
        hello["type"] = "connected";
        hello["message"] = "PaliCap metrics stream connected";
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "";
        conn->send(Json::writeString(writer, hello));
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
        if (type == drogon::WebSocketMessageType::Text) {
            try {
                // If it's a ping, respond with pong
                if (msg.find("\"ping\"") != std::string::npos) {
                    Json::Value pong;
                    pong["type"] = "pong";
                    Json::StreamWriterBuilder writer;
                    writer["indentation"] = "";
                    conn->send(Json::writeString(writer, pong));
                }
            } catch (...) {}
        }
    }

    // Pushes metrics JSON to all connected clients
    static void broadcast(const Json::Value& metrics_summary) {
        std::lock_guard<std::mutex> lk(ws_mtx_);
        if (clients_.empty()) return;
        Json::StreamWriterBuilder writer;
        writer["indentation"] = "";
        std::string payload = Json::writeString(writer, metrics_summary);
        for (auto& c : clients_) {
            if (c && c->connected())
                c->send(payload);
        }
    }

private:
    inline static std::mutex ws_mtx_;
    inline static std::vector<drogon::WebSocketConnectionPtr> clients_;
};
