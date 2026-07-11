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
#include "metrics/metrics_engine.hpp"
#include "detection/detection_engine.hpp"
#include "alert_ws_controller.hpp"
#include <memory>
#include <mutex>
#include <deque>
#include <atomic>
#include <string>
#include <cstdlib>

using namespace drogon;

// Max recent parsed packets kept in memory for the /api/packets browse endpoint.
static constexpr size_t PACKET_HISTORY_SIZE = 50000;
// Max recent closed/expired flows kept for /api/flows/closed
static constexpr size_t CLOSED_FLOW_HISTORY = 10000;

class CaptureApi : public HttpController<CaptureApi> {
public:
    CaptureApi() {
        raw_bus_          = std::make_unique<PacketBus>();
        parsed_bus_       = std::make_unique<ParsedPacketBus>();
        flow_engine_      = std::make_unique<FlowEngine>();
        metrics_engine_   = std::make_unique<MetricsEngine>();
        detection_engine_ = std::make_unique<DetectionEngine>();

        // Load detector config and restore baselines from disk
        detection_engine_->load_config("/app/config/detectors.json");
        detection_engine_->load_baselines("/app/baselines.json");

        // Connect to PostgreSQL if env var is set
        const char* dsn = std::getenv("PG_DSN");
        if (dsn) detection_engine_->connect_postgres(std::string(dsn));

        // Wire WebSocket broadcast into AlertStore
        detection_engine_->store().add_callback(
            [](const Alert& a) { AlertWsController::broadcast(a); }
        );

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

        // FlowEngine event callback — feeds MetricsEngine, DetectionEngine,
        // and captures closed-flow history
        flow_engine_->set_event_callback(
            [this](FlowEvent event, std::shared_ptr<Flow> flow) {
                // ── Feed MetricsEngine ────────────────────────────────────
                metrics_engine_->on_flow_event(event, flow);

                // ── Feed DetectionEngine (behavioral detectors) ───────────
                detection_engine_->on_flow_event(event, flow);

                // ── Capture closed/expired flow history for /api/flows/closed
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
        metrics_engine_->start_housekeeping();
        detection_engine_->start(*metrics_engine_);
    }

    ~CaptureApi() {
        if (session_)          session_->stop();
        if (detection_engine_) {
            detection_engine_->save_baselines("/app/baselines.json");
            detection_engine_->stop();
        }
        if (metrics_engine_)   metrics_engine_->stop_housekeeping();
        if (flow_engine_)      flow_engine_->stop();
        if (raw_bus_)          raw_bus_->stop();
        if (parsed_bus_)       parsed_bus_->stop();
    }

    METHOD_LIST_BEGIN
    ADD_METHOD_TO(CaptureApi::getInterfaces,      "/api/interfaces",           Get);
    ADD_METHOD_TO(CaptureApi::startCapture,       "/api/capture/start",        Post);
    ADD_METHOD_TO(CaptureApi::stopCapture,        "/api/capture/stop",         Post);
    ADD_METHOD_TO(CaptureApi::getStats,           "/api/stats",                Get);
    ADD_METHOD_TO(CaptureApi::getPackets,         "/api/packets",              Get);
    ADD_METHOD_TO(CaptureApi::getPacketStats,     "/api/packets/stats",        Get);
    // ── Flow endpoints ────────────────────────────────────────────────────────
    ADD_METHOD_TO(CaptureApi::getFlows,           "/api/flows",                Get);
    ADD_METHOD_TO(CaptureApi::getFlowStats,       "/api/flows/stats",          Get);
    ADD_METHOD_TO(CaptureApi::getClosedFlows,     "/api/flows/closed",         Get);
    ADD_METHOD_TO(CaptureApi::getFlowById,        "/api/flows/{id}",           Get);
    // ── Metrics endpoints (Module 4) ──────────────────────────────────────────
    ADD_METHOD_TO(CaptureApi::getMetricsNetwork,  "/api/metrics/network",      Get);
    ADD_METHOD_TO(CaptureApi::getMetricsTcp,      "/api/metrics/tcp",          Get);
    ADD_METHOD_TO(CaptureApi::getMetricsDns,      "/api/metrics/dns",          Get);
    ADD_METHOD_TO(CaptureApi::getMetricsHttp,     "/api/metrics/http",         Get);
    ADD_METHOD_TO(CaptureApi::getMetricsSummary,  "/api/metrics/summary",      Get);
    // ── Detection / Alert endpoints (Module 5) ────────────────────────────────
    ADD_METHOD_TO(CaptureApi::getAlerts,           "/api/alerts",               Get);
    ADD_METHOD_TO(CaptureApi::getAlertCount,       "/api/alerts/count",         Get);
    ADD_METHOD_TO(CaptureApi::suppressAlerts,      "/api/alerts/suppress",      Post);
    ADD_METHOD_TO(CaptureApi::getDetectors,        "/api/detectors",            Get);
    ADD_METHOD_TO(CaptureApi::setDetectorConfig,   "/api/detectors/{type}/config", Post);
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
        metrics_engine_->reset();

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

    // ── GET /api/metrics/network?window=60 ───────────────────────────────────
    void getMetricsNetwork(const HttpRequestPtr& req,
                            std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t window = parse_window(req);
        auto snap = metrics_engine_->network_snapshot(window);

        nlohmann::json j;
        j["window_sec"]        = window;
        j["bps_in"]            = snap.bytes_in_per_sec * 8.0;
        j["bps_out"]           = snap.bytes_out_per_sec * 8.0;
        j["bytes_in_per_sec"]  = snap.bytes_in_per_sec;
        j["bytes_out_per_sec"] = snap.bytes_out_per_sec;
        j["packets_per_sec"]   = snap.packets_per_sec;
        j["new_flows_per_sec"] = snap.new_flows_per_sec;
        j["active_flows"]      = snap.active_flows;

        j["top_talkers"] = nlohmann::json::array();
        for (auto& e : snap.top_talkers)
            j["top_talkers"].push_back({{"ip", e.key}, {"bytes", e.value}});

        j["top_destinations"] = nlohmann::json::array();
        for (auto& e : snap.top_destinations)
            j["top_destinations"].push_back({{"ip", e.key}, {"bytes", e.value}});

        j["protocol_breakdown"] = nlohmann::json::array();
        for (auto& e : snap.protocol_breakdown)
            j["protocol_breakdown"].push_back({{"protocol", e.key}, {"count", e.value}});

        send_json(cb, j);
    }

    // ── GET /api/metrics/tcp?window=60 ───────────────────────────────────────
    void getMetricsTcp(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t window = parse_window(req);
        auto snap = metrics_engine_->tcp_snapshot(window);

        nlohmann::json j;
        j["window_sec"]             = window;
        j["rtt_p50_us"]             = snap.rtt_p50_us;
        j["rtt_p95_us"]             = snap.rtt_p95_us;
        j["rtt_p99_us"]             = snap.rtt_p99_us;
        j["retransmission_rate_pct"] = snap.retransmission_rate_pct;
        j["zero_window_rate"]       = snap.zero_window_rate;
        j["avg_flow_duration_ms"]   = snap.avg_flow_duration_ms;
        j["avg_setup_time_ms"]      = snap.avg_setup_time_ms;
        j["rst_per_min"]            = snap.rst_per_min;

        j["worst_rtt_flows"] = nlohmann::json::array();
        for (auto& e : snap.worst_rtt_flows)
            j["worst_rtt_flows"].push_back({{"flow", e.key}, {"avg_rtt_ms", e.avg}});

        send_json(cb, j);
    }

    // ── GET /api/metrics/dns?window=60 ───────────────────────────────────────
    void getMetricsDns(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t window = parse_window(req);
        auto snap = metrics_engine_->dns_snapshot(window);

        nlohmann::json j;
        j["window_sec"]        = window;
        j["avg_resolution_ms"] = snap.avg_resolution_ms;
        j["p95_resolution_ms"] = snap.p95_resolution_ms;
        j["p99_resolution_ms"] = snap.p99_resolution_ms;
        j["nxdomain_rate_pct"] = snap.nxdomain_rate_pct;
        j["queries_per_sec"]   = snap.queries_per_sec;

        j["top_domains"] = nlohmann::json::array();
        for (auto& e : snap.top_domains)
            j["top_domains"].push_back({{"domain", e.key}, {"queries", e.value}});

        j["slowest_domains"] = nlohmann::json::array();
        for (auto& e : snap.slowest_domains)
            j["slowest_domains"].push_back({{"domain", e.key}, {"avg_ms", e.avg}});

        send_json(cb, j);
    }

    // ── GET /api/metrics/http?window=60 ──────────────────────────────────────
    void getMetricsHttp(const HttpRequestPtr& req,
                         std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t window = parse_window(req);
        auto snap = metrics_engine_->http_snapshot(window);

        nlohmann::json j;
        j["window_sec"]      = window;
        j["req_per_sec"]     = snap.req_per_sec;
        j["latency_p50_ms"]  = snap.latency_p50_ms;
        j["latency_p95_ms"]  = snap.latency_p95_ms;
        j["latency_p99_ms"]  = snap.latency_p99_ms;
        j["error_rate_pct"]  = snap.error_rate_pct;
        j["server_error_pct"]= snap.server_error_pct;
        j["bytes_per_sec"]   = snap.bytes_per_sec;

        j["top_endpoints"] = nlohmann::json::array();
        for (auto& e : snap.top_endpoints)
            j["top_endpoints"].push_back({{"endpoint", e.key}, {"requests", e.value}});

        j["slowest_endpoints"] = nlohmann::json::array();
        for (auto& e : snap.slowest_endpoints)
            j["slowest_endpoints"].push_back({{"endpoint", e.key}, {"avg_ms", e.avg}});

        j["top_hosts"] = nlohmann::json::array();
        for (auto& e : snap.top_hosts)
            j["top_hosts"].push_back({{"host", e.key}, {"requests", e.value}});

        j["status_breakdown"] = nlohmann::json::array();
        for (auto& e : snap.status_breakdown)
            j["status_breakdown"].push_back({{"status", e.key}, {"count", e.value}});

        send_json(cb, j);
    }

    // ── GET /api/metrics/summary?window=60 ───────────────────────────────────
    void getMetricsSummary(const HttpRequestPtr& req,
                            std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t window = parse_window(req);
        auto ctx = metrics_engine_->ai_context_snapshot(window);
        // ai_context_snapshot already produces the combined JSON
        send_json(cb, ctx);
    }

private:
    // ── Helpers ───────────────────────────────────────────────────────────────
    static size_t parse_window(const HttpRequestPtr& req) {
        size_t window = 60;
        auto wp = req->getParameter("window");
        if (!wp.empty()) {
            try { window = std::max(size_t(1), std::min((size_t)std::stoul(wp), size_t(3600))); }
            catch (...) {}
        }
        return window;
    }

    static void send_json(std::function<void(const HttpResponsePtr&)>& cb,
                          const nlohmann::json& j) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k200OK);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(j.dump());
        cb(resp);
    }

    // ── GET /api/alerts ──────────────────────────────────────────────────────
    void getAlerts(const HttpRequestPtr& req,
                   std::function<void(const HttpResponsePtr&)>&& cb) const {
        size_t n = 100;
        auto np = req->getParameter("n");
        if (!np.empty()) { try { n = std::min((size_t)std::stoul(np), size_t(1000)); } catch(...){} }

        AlertSeverity min_sev = AlertSeverity::INFO;
        auto sevp = req->getParameter("severity");
        if (sevp == "WARNING")  min_sev = AlertSeverity::WARNING;
        if (sevp == "CRITICAL") min_sev = AlertSeverity::CRITICAL;

        auto typep = req->getParameter("type");
        std::vector<Alert> alerts;

        // type filter — search by AlertType name
        if (!typep.empty()) {
            // Walk all alerts and match by type string
            auto all = detection_engine_->store().recent(10000, AlertSeverity::INFO);
            for (auto& a : all)
                if (std::string(alert_type_str(a.type)) == typep)
                    alerts.push_back(a);
            if (alerts.size() > n) alerts.resize(n);
        } else {
            alerts = detection_engine_->store().recent(n, min_sev);
        }

        nlohmann::json j = nlohmann::json::array();
        for (auto& a : alerts) j.push_back(a.to_json());
        send_json(cb, j);
    }

    // ── GET /api/alerts/count ────────────────────────────────────────────────
    void getAlertCount(const HttpRequestPtr& req,
                       std::function<void(const HttpResponsePtr&)>&& cb) const {
        // Count alerts in last hour by default
        auto since = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()
            - 3'600'000'000'000LL;
        auto c = detection_engine_->store().count_recent(since);
        send_json(cb, {
            {"info",     c.info},
            {"warning",  c.warning},
            {"critical", c.critical},
            {"total",    c.info + c.warning + c.critical}
        });
    }

    // ── POST /api/alerts/suppress?duration_sec=N ─────────────────────────────
    void suppressAlerts(const HttpRequestPtr& req,
                        std::function<void(const HttpResponsePtr&)>&& cb) {
        int64_t dur_sec = 3600;
        auto dp = req->getParameter("duration_sec");
        if (!dp.empty()) { try { dur_sec = std::max(int64_t(1), (int64_t)std::stoll(dp)); } catch(...){} }
        detection_engine_->suppress(dur_sec * 1'000'000'000LL);
        send_json(cb, {{"suppressed_for_sec", dur_sec},
                       {"is_suppressed", true}});
    }

    // ── GET /api/detectors ───────────────────────────────────────────────────
    void getDetectors(const HttpRequestPtr& req,
                      std::function<void(const HttpResponsePtr&)>&& cb) const {
        send_json(cb, detection_engine_->detector_status());
    }

    // ── POST /api/detectors/{type}/config ────────────────────────────────────
    void setDetectorConfig(const HttpRequestPtr& req,
                           std::function<void(const HttpResponsePtr&)>&& cb,
                           std::string type) {
        auto body = req->getBody();
        try {
            auto cfg = nlohmann::json::parse(body);
            detection_engine_->set_detector_config(type, cfg);
            send_json(cb, {{"status", "updated"}, {"detector", type}});
        } catch (const std::exception& e) {
            nlohmann::json err = {{"error", e.what()}};
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k400BadRequest);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(err.dump());
            cb(resp);
        }
    }

    mutable std::mutex              ctrl_mutex_;
    mutable std::mutex              history_mutex_;
    mutable std::mutex              closed_flows_mutex_;
    std::unique_ptr<PacketBus>      raw_bus_;
    std::unique_ptr<ParsedPacketBus>parsed_bus_;
    std::unique_ptr<CaptureSession> session_;
    std::unique_ptr<FlowEngine>     flow_engine_;
    std::unique_ptr<MetricsEngine>  metrics_engine_;
    std::unique_ptr<DetectionEngine>detection_engine_;
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
