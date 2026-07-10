#pragma once

#include "parsed_packet.hpp"
#include <nlohmann/json.hpp>
#include <string>

inline nlohmann::json to_json(const ParsedPacket& p) {
    nlohmann::json j;
    j["id"]           = p.packet_id;
    j["timestamp_ns"] = p.timestamp_ns;
    j["captured_len"] = p.captured_len;
    j["original_len"] = p.original_len;
    j["interface"]    = p.interface_name;
    j["truncated"]    = p.is_truncated;
    j["app_protocol"] = app_protocol_str(p.app_protocol);

    if (!p.parse_error.empty()) j["parse_error"] = p.parse_error;

    if (p.eth) {
        j["eth"]["src"]       = p.eth->src_mac_str;
        j["eth"]["dst"]       = p.eth->dst_mac_str;
        j["eth"]["ethertype"] = p.eth->ethertype;
    }
    if (p.vlan) {
        j["vlan"]["id"]       = p.vlan->vlan_id;
        j["vlan"]["priority"] = p.vlan->priority;
    }
    if (p.arp) {
        j["arp"]["op"]         = p.arp->operation;
        j["arp"]["sender_mac"] = p.arp->sender_mac;
        j["arp"]["sender_ip"]  = p.arp->sender_ip;
        j["arp"]["target_ip"]  = p.arp->target_ip;
    }
    if (p.ip4) {
        j["ip"]["version"]  = 4;
        j["ip"]["src"]      = p.ip4->src_ip_str;
        j["ip"]["dst"]      = p.ip4->dst_ip_str;
        j["ip"]["ttl"]      = p.ip4->ttl;
        j["ip"]["protocol"] = p.ip4->protocol;
        j["ip"]["dscp"]     = p.ip4->dscp;
        j["ip"]["ecn"]      = p.ip4->ecn;
        j["ip"]["len"]      = p.ip4->total_len;
        if (p.ip4->is_fragment) {
            j["ip"]["fragment"]    = true;
            j["ip"]["frag_offset"] = p.ip4->frag_offset;
        }
    }
    if (p.ip6) {
        j["ip"]["version"]       = 6;
        j["ip"]["src"]           = p.ip6->src_ip_str;
        j["ip"]["dst"]           = p.ip6->dst_ip_str;
        j["ip"]["hop_limit"]     = p.ip6->hop_limit;
        j["ip"]["next_header"]   = p.ip6->next_header;
        j["ip"]["flow_label"]    = p.ip6->flow_label;
        j["ip"]["dscp"]          = p.ip6->dscp;
        j["ip"]["ecn"]           = p.ip6->ecn;
    }
    if (p.icmp) {
        j["icmp"]["type"] = p.icmp->type;
        j["icmp"]["code"] = p.icmp->code;
        j["icmp"]["id"]   = p.icmp->id;
        j["icmp"]["seq"]  = p.icmp->seq;
    }
    if (p.icmpv6) {
        j["icmpv6"]["type"] = p.icmpv6->type;
        j["icmpv6"]["code"] = p.icmpv6->code;
        j["icmpv6"]["id"]   = p.icmpv6->id;
        j["icmpv6"]["seq"]  = p.icmpv6->seq;
    }
    if (p.tcp) {
        j["tcp"]["src_port"]  = p.tcp->src_port;
        j["tcp"]["dst_port"]  = p.tcp->dst_port;
        j["tcp"]["seq"]       = p.tcp->seq_num;
        j["tcp"]["ack"]       = p.tcp->ack_num;
        j["tcp"]["window"]    = p.tcp->window_size;
        j["tcp"]["payload_len"] = p.tcp->payload_len;
        j["tcp"]["flags"] = {
            {"syn", p.tcp->flag_syn}, {"ack", p.tcp->flag_ack},
            {"fin", p.tcp->flag_fin}, {"rst", p.tcp->flag_rst},
            {"psh", p.tcp->flag_psh}, {"urg", p.tcp->flag_urg},
            {"ece", p.tcp->flag_ece}, {"cwr", p.tcp->flag_cwr}
        };
        if (p.tcp->mss)           j["tcp"]["mss"]          = *p.tcp->mss;
        if (p.tcp->window_scale)  j["tcp"]["window_scale"] = *p.tcp->window_scale;
        if (p.tcp->actual_window) j["tcp"]["actual_window"]= p.tcp->actual_window;
        if (p.tcp->ts_val)        j["tcp"]["ts_val"]       = *p.tcp->ts_val;
        if (p.tcp->ts_ecr)        j["tcp"]["ts_ecr"]       = *p.tcp->ts_ecr;
        if (p.tcp->sack_permitted) j["tcp"]["sack_permitted"] = true;
        if (!p.tcp->sack_blocks.empty()) {
            auto& sb = j["tcp"]["sack_blocks"];
            for (auto& [l, r] : p.tcp->sack_blocks)
                sb.push_back({{"left", l}, {"right", r}});
        }
    }
    if (p.udp) {
        j["udp"]["src_port"]    = p.udp->src_port;
        j["udp"]["dst_port"]    = p.udp->dst_port;
        j["udp"]["payload_len"] = p.udp->payload_len;
    }
    if (p.dns) {
        j["dns"]["txid"]        = p.dns->transaction_id;
        j["dns"]["query"]       = p.dns->query_name;
        j["dns"]["type"]        = p.dns->query_type;
        j["dns"]["is_response"] = p.dns->is_response;
        j["dns"]["rcode"]       = p.dns->rcode;
        j["dns"]["answers"]     = p.dns->answers;
    }
    if (p.http) {
        if (p.http->is_request) {
            j["http"]["method"]  = p.http->method;
            j["http"]["url"]     = p.http->url;
            j["http"]["host"]    = p.http->host;
            j["http"]["version"] = p.http->http_version;
            if (!p.http->user_agent.empty()) j["http"]["user_agent"] = p.http->user_agent;
            if (!p.http->referer.empty())    j["http"]["referer"]    = p.http->referer;
        } else {
            j["http"]["status"]  = p.http->status_code;
            j["http"]["message"] = p.http->status_message;
            j["http"]["version"] = p.http->http_version;
            j["http"]["size"]    = p.http->response_size;
        }
    }
    if (p.tls) {
        j["tls"]["version"]        = p.tls->tls_version_str;
        j["tls"]["record_type"]    = p.tls->record_type;
        j["tls"]["handshake_type"] = p.tls->handshake_type;
        if (!p.tls->sni.empty())  j["tls"]["sni"]  = p.tls->sni;
        if (!p.tls->alpn.empty()) j["tls"]["alpn"] = p.tls->alpn;
        if (p.tls->alert_level)   j["tls"]["alert"] = {
            {"level", p.tls->alert_level},
            {"description", p.tls->alert_description}
        };
    }
    if (p.flow_key.valid) {
        j["flow"]["src"]       = p.flow_key.src_ip + ":" + std::to_string(p.flow_key.src_port);
        j["flow"]["dst"]       = p.flow_key.dst_ip + ":" + std::to_string(p.flow_key.dst_port);
        j["flow"]["protocol"]  = p.flow_key.protocol;
        j["flow"]["canonical"] = p.flow_key.canonical();
    }
    return j;
}
