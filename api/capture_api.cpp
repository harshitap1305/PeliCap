#include <drogon/HttpController.h>
#include "capture/interface_discovery.hpp"
#include "capture/capture_session.hpp"
#include "capture/pcap_loader.hpp"
#include "dispatch/packet_bus.hpp"
#include "dispatch/parsed_packet_bus.hpp"
#include "dissector/dissector_engine.hpp"
#include "dissector/serializer.hpp"
#include <memory>
#include <mutex>
#include <deque>
#include <atomic>

using namespace drogon;

// Max recent parsed packets kept in memory for the /api/packets browse endpoint.
// Analytics accuracy is NOT affected — every packet still flows through the engine.
static constexpr size_t PACKET_HISTORY_SIZE = 50000;

class CaptureApi : public HttpController<CaptureApi> {
public:
    CaptureApi() {
        raw_bus_    = std::make_unique<PacketBus>();
        parsed_bus_ = std::make_unique<ParsedPacketBus>();

        // Dissector subscriber: raw packet → ParsedPacket → ParsedPacketBus
        raw_bus_->subscribe([this](const CapturedPacket& raw) {
            total_raw_++;
            auto* pp = new ParsedPacket(DissectorEngine::dissect(raw));
            if (!parsed_bus_->publish(pp)) {
                parsed_dropped_++;
                delete pp;
            }
        });

        // Analytics subscriber on parsed bus
        parsed_bus_->subscribe([this](const ParsedPacket& pp) {
            total_parsed_++;
            // Protocol counters
            switch (pp.app_protocol) {
                case AppProtocol::HTTP:   proto_http_++;   break;
                case AppProtocol::HTTPS:
                case AppProtocol::HTTP2:
                case AppProtocol::HTTP3:  proto_tls_++;    break;
                case AppProtocol::DNS:
                case AppProtocol::DNS_TLS:proto_dns_++;    break;
                case AppProtocol::ICMP:
                case AppProtocol::ICMPv6: proto_icmp_++;   break;
                case AppProtocol::ARP:    proto_arp_++;    break;
                default: break;
            }
            // History ring buffer — for /api/packets browse endpoint
            {
                std::lock_guard<std::mutex> lk(history_mutex_);
                history_.push_back(to_json(pp));
                if (history_.size() > PACKET_HISTORY_SIZE)
                    history_.pop_front();
            }
        });

        raw_bus_->start();
        parsed_bus_->start();
    }

    ~CaptureApi() {
        if (session_) session_->stop();
        if (raw_bus_) raw_bus_->stop();
        if (parsed_bus_) parsed_bus_->stop();
    }

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CaptureApi::getInterfaces,   "/api/interfaces",       Get);
    ADD_METHOD_TO(CaptureApi::startCapture,    "/api/capture/start",    Post);
    ADD_METHOD_TO(CaptureApi::stopCapture,     "/api/capture/stop",     Post);
    ADD_METHOD_TO(CaptureApi::getStats,        "/api/stats",            Get);
    ADD_METHOD_TO(CaptureApi::getPackets,      "/api/packets",          Get);
    ADD_METHOD_TO(CaptureApi::getPacketStats,  "/api/packets/stats",    Get);
    METHOD_LIST_END

    // ── GET /api/interfaces ──────────────────────────────────────────────────
    void getInterfaces(const HttpRequestPtr& req,
                       std::function<void(const HttpResponsePtr&)>&& cb) const {
        auto ifaces = list_interfaces();
        Json::Value ret;
        for (auto& i : ifaces) {
            Json::Value info;
            info["name"]        = i.name;
            info["description"] = i.description;
            info["ip_address"]  = i.ip_address;
            info["mac_address"] = i.mac_address;
            info["is_loopback"] = i.is_loopback;
            ret.append(info);
        }
        cb(HttpResponse::newHttpJsonResponse(ret));
    }

    // ── POST /api/capture/start ──────────────────────────────────────────────
    void startCapture(const HttpRequestPtr& req,
                      std::function<void(const HttpResponsePtr&)>&& cb) {
        std::lock_guard<std::mutex> lk(ctrl_mutex_);
        auto json = req->getJsonObject();
        if (!json) {
            auto r = HttpResponse::newHttpResponse();
            r->setStatusCode(k400BadRequest);
            cb(r); return;
        }
        if (session_) { session_->stop(); session_.reset(); }
        {
            std::lock_guard<std::mutex> lk2(history_mutex_);
            history_.clear();
        }
        total_raw_ = 0; total_parsed_ = 0; parsed_dropped_ = 0;
        proto_http_ = proto_tls_ = proto_dns_ = proto_icmp_ = proto_arp_ = 0;

        CaptureSession::Config cfg;
        cfg.interface_name = (*json)["interface"].asString();
        cfg.bpf_filter     = (*json)["bpf_filter"].asString();
        cfg.promiscuous    = (*json).get("promiscuous", true).asBool();
        try {
            session_ = std::make_unique<CaptureSession>(cfg, *raw_bus_);
            session_->start();
            Json::Value r; r["status"] = "started";
            cb(HttpResponse::newHttpJsonResponse(r));
        } catch (const std::exception& e) {
            Json::Value r; r["error"] = e.what();
            auto resp = HttpResponse::newHttpJsonResponse(r);
            resp->setStatusCode(k500InternalServerError);
            cb(resp);
        }
    }

    // ── POST /api/capture/stop ───────────────────────────────────────────────
    void stopCapture(const HttpRequestPtr& req,
                     std::function<void(const HttpResponsePtr&)>&& cb) {
        std::lock_guard<std::mutex> lk(ctrl_mutex_);
        if (session_) { session_->stop(); session_.reset(); }
        Json::Value r; r["status"] = "stopped";
        cb(HttpResponse::newHttpJsonResponse(r));
    }

    // ── GET /api/stats ───────────────────────────────────────────────────────
    void getStats(const HttpRequestPtr& req,
                  std::function<void(const HttpResponsePtr&)>&& cb) const {
        Json::Value r;
        r["packets_captured"] = Json::UInt64(session_ ? session_->packets_captured() : 0ULL);
        r["packets_dropped"]  = Json::UInt64(session_ ? session_->packets_dropped()  : 0ULL);
        r["total_raw"]        = Json::UInt64(total_raw_.load());
        r["total_parsed"]     = Json::UInt64(total_parsed_.load());
        r["parsed_dropped"]   = Json::UInt64(parsed_dropped_.load());
        r["capturing"]        = (session_ != nullptr);
        cb(HttpResponse::newHttpJsonResponse(r));
    }

    // ── GET /api/packets?limit=N ─────────────────────────────────────────────
    void getPackets(const HttpRequestPtr& req,
                    std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t limit = 100;
        auto lp = req->getParameter("limit");
        if (!lp.empty()) try { limit = std::min((size_t)std::stoul(lp), (size_t)5000); } catch (...) {}

        // Build response as a raw JSON string to avoid double-encoding nlohmann→jsoncpp
        nlohmann::json result;
        {
            std::lock_guard<std::mutex> lk(history_mutex_);
            size_t start = history_.size() > limit ? history_.size() - limit : 0;
            result["count"]   = history_.size() - start;
            result["packets"] = nlohmann::json::array();
            for (size_t i = start; i < history_.size(); ++i)
                result["packets"].push_back(history_[i]);
        }
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(result.dump());
        cb(resp);
    }

    // ── GET /api/packets/stats ───────────────────────────────────────────────
    void getPacketStats(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& cb) const {
        Json::Value r;
        r["total"]   = Json::UInt64(total_parsed_.load());
        r["http"]    = Json::UInt64(proto_http_.load());
        r["tls"]     = Json::UInt64(proto_tls_.load());
        r["dns"]     = Json::UInt64(proto_dns_.load());
        r["icmp"]    = Json::UInt64(proto_icmp_.load());
        r["arp"]     = Json::UInt64(proto_arp_.load());
        r["other"]   = Json::UInt64(total_parsed_.load()
                         - proto_http_ - proto_tls_ - proto_dns_ - proto_icmp_ - proto_arp_);
        cb(HttpResponse::newHttpJsonResponse(r));
    }

private:
    mutable std::mutex              ctrl_mutex_;
    mutable std::mutex              history_mutex_;
    std::unique_ptr<PacketBus>      raw_bus_;
    std::unique_ptr<ParsedPacketBus>parsed_bus_;
    std::unique_ptr<CaptureSession> session_;
    std::deque<nlohmann::json>      history_;

    std::atomic<uint64_t> total_raw_{0};
    std::atomic<uint64_t> total_parsed_{0};
    std::atomic<uint64_t> parsed_dropped_{0};
    std::atomic<uint64_t> proto_http_{0};
    std::atomic<uint64_t> proto_tls_{0};
    std::atomic<uint64_t> proto_dns_{0};
    std::atomic<uint64_t> proto_icmp_{0};
    std::atomic<uint64_t> proto_arp_{0};
};
