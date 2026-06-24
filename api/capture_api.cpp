#include <drogon/HttpController.h>
#include "capture/interface_discovery.hpp"
#include "capture/capture_session.hpp"
#include "capture/pcap_loader.hpp"
#include "dispatch/packet_bus.hpp"
#include <memory>
#include <mutex>

using namespace drogon;

class CaptureApi : public HttpController<CaptureApi> {
public:
    CaptureApi() {
        bus_ = std::make_unique<PacketBus>();
        bus_->subscribe([this](const CapturedPacket& pkt) {
            total_processed_++;
        });
        bus_->start();
    }

    ~CaptureApi() {
        if (session_) session_->stop();
        if (bus_) bus_->stop();
    }

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CaptureApi::getInterfaces, "/api/interfaces", Get);
    ADD_METHOD_TO(CaptureApi::startCapture, "/api/capture/start", Post);
    ADD_METHOD_TO(CaptureApi::stopCapture, "/api/capture/stop", Post);
    ADD_METHOD_TO(CaptureApi::getStats, "/api/stats", Get);
    METHOD_LIST_END

    void getInterfaces(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const {
        auto interfaces = list_interfaces();
        Json::Value ret;
        for (const auto& iface : interfaces) {
            Json::Value info;
            info["name"] = iface.name;
            info["description"] = iface.description;
            info["ip_address"] = iface.ip_address;
            info["mac_address"] = iface.mac_address;
            info["is_loopback"] = iface.is_loopback;
            ret.append(info);
        }
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        callback(resp);
    }

    void startCapture(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto json = req->getJsonObject();
        if (!json) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k400BadRequest);
            callback(resp);
            return;
        }

        if (session_) {
            session_->stop();
            session_.reset();
        }

        CaptureSession::Config cfg;
        cfg.interface_name = (*json)["interface"].asString();
        cfg.bpf_filter = (*json)["bpf_filter"].asString();
        cfg.promiscuous = (*json).get("promiscuous", true).asBool();

        try {
            session_ = std::make_unique<CaptureSession>(cfg, *bus_);
            session_->start();
            
            Json::Value ret;
            ret["status"] = "started";
            callback(HttpResponse::newHttpJsonResponse(ret));
        } catch (const std::exception& e) {
            Json::Value ret;
            ret["error"] = e.what();
            auto resp = HttpResponse::newHttpJsonResponse(ret);
            resp->setStatusCode(k500InternalServerError);
            callback(resp);
        }
    }

    void stopCapture(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (session_) {
            session_->stop();
            session_.reset();
        }
        Json::Value ret;
        ret["status"] = "stopped";
        callback(HttpResponse::newHttpJsonResponse(ret));
    }

    void getStats(const HttpRequestPtr& req, std::function<void(const HttpResponsePtr&)>&& callback) const {
        Json::Value ret;
        if (session_) {
            ret["packets_captured"] = (Json::UInt64)session_->packets_captured();
            ret["packets_dropped"] = (Json::UInt64)session_->packets_dropped();
        } else {
            ret["packets_captured"] = 0;
            ret["packets_dropped"] = 0;
        }
        ret["total_processed"] = (Json::UInt64)total_processed_.load();
        callback(HttpResponse::newHttpJsonResponse(ret));
    }

private:
    std::mutex mutex_;
    std::unique_ptr<PacketBus> bus_;
    std::unique_ptr<CaptureSession> session_;
    std::atomic<uint64_t> total_processed_{0};
};
