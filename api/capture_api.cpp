#include <drogon/HttpController.h>
#include "capture/interface_discovery.hpp"
#include "capture/capture_session.hpp"
#include "capture/pcap_loader.hpp"
#include "dispatch/packet_bus.hpp"
#include "dispatch/parsed_packet_bus.hpp"
#include "dissector/dissector_engine.hpp"
#include "dissector/serializer.hpp"
#include "flow/flow_engine.hpp"
#include "flow/flow_serializer.hpp"
#include <memory>
#include <mutex>
#include <deque>
#include <atomic>
#include <string>

using namespace drogon;

// Max recent parsed packets kept in memory for the /api/packets browse endpoint.
static constexpr size_t PACKET_HISTORY_SIZE = 50000;
// Max recent closed/expired flows kept for /api/flows/closed
static constexpr size_t CLOSED_FLOW_HISTORY = 10000;

class CaptureApi : public HttpController<CaptureApi> {
public:
    CaptureApi() {
        raw_bus_    = std::make_unique<PacketBus>();
        parsed_bus_ = std::make_unique<ParsedPacketBus>();
        flow_engine_= std::make_unique<FlowEngine>();

        // ── Raw → Dissect → ParsedPacketBus ──────────────────────────────────
        raw_bus_->subscribe([this](const CapturedPacket& raw) {
            total_raw_++;
            auto* pp = new ParsedPacket(DissectorEngine::dissect(raw));
            if (!parsed_bus_->publish(pp)) {
                parsed_dropped_++;
                delete pp;
            }
        });

        // ── Analytics subscriber ──────────────────────────────────────────────
        parsed_bus_->subscribe([this](const ParsedPacket& pp) {
            total_parsed_++;
            switch (pp.app_protocol) {
                case AppProtocol::HTTP:    proto_http_++;  break;
                case AppProtocol::HTTPS:
                case AppProtocol::HTTP2:
                case AppProtocol::HTTP3:   proto_tls_++;   break;
                case AppProtocol::DNS:
                case AppProtocol::DNS_TLS: proto_dns_++;   break;
                case AppProtocol::ICMP:
                case AppProtocol::ICMPv6:  proto_icmp_++;  break;
                case AppProtocol::ARP:     proto_arp_++;   break;
                default: break;
            }
            // Packet history ring buffer
            {
                std::lock_guard<std::mutex> lk(history_mutex_);
                history_.push_back(to_json(pp));
                if (history_.size() > PACKET_HISTORY_SIZE)
                    history_.pop_front();
            }
        });

        // ── FlowEngine subscriber ─────────────────────────────────────────────
        parsed_bus_->subscribe([this](const ParsedPacket& pp) {
            flow_engine_->process(pp);
        });

        // FlowEngine event callback — captures CLOSED/EXPIRED flows into history
        flow_engine_->set_event_callback(
            [this](FlowEvent event, std::shared_ptr<Flow> flow) {
                if (event == FlowEvent::CLOSED || event == FlowEvent::EXPIRED) {
                    std::lock_guard<std::mutex> lk(closed_flows_mutex_);
                    closed_flows_.push_back(flow_to_json(*flow));
                    if (closed_flows_.size() > CLOSED_FLOW_HISTORY)
                        closed_flows_.pop_front();
                }
            }
        );

        raw_bus_->start();
        parsed_bus_->start();
        flow_engine_->start();
    }

    ~CaptureApi() {
        if (session_)     session_->stop();
        if (flow_engine_) flow_engine_->stop();
        if (raw_bus_)     raw_bus_->stop();
        if (parsed_bus_)  parsed_bus_->stop();
    }

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CaptureApi::getInterfaces,   "/api/interfaces",        Get);
    ADD_METHOD_TO(CaptureApi::startCapture,    "/api/capture/start",     Post);
    ADD_METHOD_TO(CaptureApi::stopCapture,     "/api/capture/stop",      Post);
    ADD_METHOD_TO(CaptureApi::getStats,        "/api/stats",             Get);
    ADD_METHOD_TO(CaptureApi::getPackets,      "/api/packets",           Get);
    ADD_METHOD_TO(CaptureApi::getPacketStats,  "/api/packets/stats",     Get);
    // ── Flow endpoints ────────────────────────────────────────────────────────
    ADD_METHOD_TO(CaptureApi::getFlows,        "/api/flows",             Get);
    ADD_METHOD_TO(CaptureApi::getFlowStats,    "/api/flows/stats",       Get);
    ADD_METHOD_TO(CaptureApi::getClosedFlows,  "/api/flows/closed",      Get);
    ADD_METHOD_TO(CaptureApi::getFlowById,     "/api/flows/{id}",        Get);
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

        // Reset all state for new capture session
        {
            std::lock_guard<std::mutex> lk2(history_mutex_);
            history_.clear();
        }
        {
            std::lock_guard<std::mutex> lk3(closed_flows_mutex_);
            closed_flows_.clear();
        }
        flow_engine_->reset();

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
        r["active_flows"]     = Json::UInt64(flow_engine_->active_flows());
        r["capturing"]        = (session_ != nullptr);
        cb(HttpResponse::newHttpJsonResponse(r));
    }

    // ── GET /api/packets?limit=N ─────────────────────────────────────────────
    void getPackets(const HttpRequestPtr& req,
                    std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t limit = 100;
        auto lp = req->getParameter("limit");
        if (!lp.empty()) try { limit = std::min((size_t)std::stoul(lp), (size_t)5000); } catch (...) {}

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
        r["https"]   = Json::UInt64(proto_tls_.load());
        r["dns"]     = Json::UInt64(proto_dns_.load());
        r["icmp"]    = Json::UInt64(proto_icmp_.load());
        r["arp"]     = Json::UInt64(proto_arp_.load());
        r["other"]   = Json::UInt64(total_parsed_.load()
                         - proto_http_ - proto_tls_ - proto_dns_ - proto_icmp_ - proto_arp_);
        cb(HttpResponse::newHttpJsonResponse(r));
    }

    // ── GET /api/flows ───────────────────────────────────────────────────────
    // Filters: limit, offset, src_ip, dst_ip, protocol, state, sni
    void getFlows(const HttpRequestPtr& req,
                  std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t limit  = 100, offset = 0;
        auto lp = req->getParameter("limit");
        auto op = req->getParameter("offset");
        if (!lp.empty()) try { limit  = std::min((size_t)std::stoul(lp), (size_t)5000); } catch (...) {}
        if (!op.empty()) try { offset = std::stoul(op); } catch (...) {}

        std::string f_src_ip   = req->getParameter("src_ip");
        std::string f_dst_ip   = req->getParameter("dst_ip");
        std::string f_protocol = req->getParameter("protocol");
        std::string f_state    = req->getParameter("state");
        std::string f_sni      = req->getParameter("sni");

        auto all = flow_engine_->snapshot_flows();

        // Apply filters
        nlohmann::json arr = nlohmann::json::array();
        size_t matched = 0, idx = 0;
        for (auto& flow : all) {
            std::lock_guard<std::mutex> lk(flow->mtx_);
            // Filter checks
            if (!f_src_ip.empty()   && flow->src_ip_str != f_src_ip)   continue;
            if (!f_dst_ip.empty()   && flow->dst_ip_str != f_dst_ip)   continue;
            if (!f_sni.empty()      && flow->tls_sni    != f_sni)      continue;
            if (!f_protocol.empty()) {
                std::string p = (flow->protocol == 6) ? "TCP" :
                                (flow->protocol == 17) ? "UDP" : "OTHER";
                if (p != f_protocol) continue;
            }
            if (!f_state.empty() && flow->protocol == 6) {
                if (std::string(tcp_state_str(flow->tcp_state)) != f_state) continue;
            }

            ++matched;
            if (idx++ < offset) continue;
            if (arr.size() >= limit) continue;
            arr.push_back(flow_to_summary_json(*flow));
        }

        nlohmann::json result;
        result["flows"]  = arr;
        result["total"]  = matched;
        result["active"] = flow_engine_->active_flows();

        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(result.dump());
        cb(resp);
    }

    // ── GET /api/flows/stats ─────────────────────────────────────────────────
    void getFlowStats(const HttpRequestPtr& req,
                      std::function<void(const HttpResponsePtr&)>&& cb) const {
        auto all = flow_engine_->snapshot_flows();

        uint64_t tcp = 0, udp = 0, dns_f = 0, icmp_f = 0, mid_stream = 0;
        uint64_t retransmits = 0, zero_windows = 0, total_rtt_us = 0, rtt_count = 0;
        uint64_t min_rtt = UINT64_MAX;

        for (auto& flow : all) {
            std::lock_guard<std::mutex> lk(flow->mtx_);
            if (flow->protocol == 6)  ++tcp;
            if (flow->protocol == 17) ++udp;
            if (flow->app_protocol == AppProtocol::DNS)  ++dns_f;
            if (flow->app_protocol == AppProtocol::ICMP) ++icmp_f;
            if (flow->tcp_state == TcpFlowState::MID_STREAM) ++mid_stream;
            retransmits  += flow->retransmit.count;
            zero_windows += flow->zero_window_events;
            uint32_t avg = flow->rtt.avg();
            if (avg > 0) { total_rtt_us += avg; ++rtt_count; min_rtt = std::min(min_rtt, (uint64_t)flow->rtt.min()); }
        }

        nlohmann::json r;
        r["total"]        = all.size();
        r["tcp"]          = tcp;
        r["udp"]          = udp;
        r["dns"]          = dns_f;
        r["icmp"]         = icmp_f;
        r["mid_stream"]   = mid_stream;
        r["retransmits"]  = retransmits;
        r["zero_windows"] = zero_windows;
        r["avg_rtt_us"]   = rtt_count > 0 ? total_rtt_us / rtt_count : 0;
        r["min_rtt_us"]   = min_rtt == UINT64_MAX ? 0 : min_rtt;

        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(r.dump());
        cb(resp);
    }

    // ── GET /api/flows/closed?limit=N ────────────────────────────────────────
    void getClosedFlows(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t limit = 100;
        auto lp = req->getParameter("limit");
        if (!lp.empty()) try { limit = std::min((size_t)std::stoul(lp), (size_t)5000); } catch (...) {}

        nlohmann::json result;
        {
            std::lock_guard<std::mutex> lk(closed_flows_mutex_);
            size_t start = closed_flows_.size() > limit ? closed_flows_.size() - limit : 0;
            result["count"]  = closed_flows_.size() - start;
            result["flows"]  = nlohmann::json::array();
            for (size_t i = start; i < closed_flows_.size(); ++i)
                result["flows"].push_back(closed_flows_[i]);
        }
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(result.dump());
        cb(resp);
    }

    // ── GET /api/flows/{id} ──────────────────────────────────────────────────
    void getFlowById(const HttpRequestPtr& req,
                     std::function<void(const HttpResponsePtr&)>&& cb,
                     uint64_t id) const {
        auto flow = flow_engine_->find_flow_by_id(id);
        if (!flow) {
            auto r = HttpResponse::newHttpResponse();
            r->setStatusCode(k404NotFound);
            cb(r); return;
        }
        std::lock_guard<std::mutex> lk(flow->mtx_);
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(flow_to_json(*flow).dump());
        cb(resp);
    }

private:
    mutable std::mutex              ctrl_mutex_;
    mutable std::mutex              history_mutex_;
    mutable std::mutex              closed_flows_mutex_;
    std::unique_ptr<PacketBus>      raw_bus_;
    std::unique_ptr<ParsedPacketBus>parsed_bus_;
    std::unique_ptr<CaptureSession> session_;
    std::unique_ptr<FlowEngine>     flow_engine_;
    std::deque<nlohmann::json>      history_;
    std::deque<nlohmann::json>      closed_flows_;

    std::atomic<uint64_t> total_raw_{0};
    std::atomic<uint64_t> total_parsed_{0};
    std::atomic<uint64_t> parsed_dropped_{0};
    std::atomic<uint64_t> proto_http_{0};
    std::atomic<uint64_t> proto_tls_{0};
    std::atomic<uint64_t> proto_dns_{0};
    std::atomic<uint64_t> proto_icmp_{0};
    std::atomic<uint64_t> proto_arp_{0};
};
