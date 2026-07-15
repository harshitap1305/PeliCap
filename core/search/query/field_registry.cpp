#include "field_registry.hpp"

namespace search {
namespace query {

// Static registry of all searchable fields
static const std::unordered_map<std::string, FieldMeta> REGISTRY = {
    {"src_ip",           {FieldId::SRC_IP,           "src_ip",           "src_ip",           FieldType::IP}},
    {"dst_ip",           {FieldId::DST_IP,           "dst_ip",           "dst_ip",           FieldType::IP}},
    {"src_port",         {FieldId::SRC_PORT,         "src_port",         "src_port",         FieldType::PORT}},
    {"dst_port",         {FieldId::DST_PORT,         "dst_port",         "dst_port",         FieldType::PORT}},
    {"protocol",         {FieldId::PROTOCOL,         "protocol",         "protocol",         FieldType::INTEGER}},
    {"interface",        {FieldId::INTERFACE_NAME,   "interface",        "interface_name",   FieldType::STRING}},
    {"start_time",       {FieldId::START_TIME,       "start_time",       "start_time",       FieldType::TIMESTAMP}},
    {"end_time",         {FieldId::END_TIME,         "end_time",         "end_time",         FieldType::TIMESTAMP}},
    {"duration_ms",      {FieldId::DURATION_MS,      "duration_ms",      "duration_ms",      FieldType::INTEGER}},
    {"bytes",            {FieldId::BYTES,            "bytes",            "(fwd_bytes + rev_bytes)", FieldType::INTEGER}},
    {"fwd_bytes",        {FieldId::FWD_BYTES,        "fwd_bytes",        "fwd_bytes",        FieldType::INTEGER}},
    {"rev_bytes",        {FieldId::REV_BYTES,        "rev_bytes",        "rev_bytes",        FieldType::INTEGER}},
    {"packets",          {FieldId::PACKETS,          "packets",          "(fwd_packets + rev_packets)", FieldType::INTEGER}},
    {"fwd_packets",      {FieldId::FWD_PACKETS,      "fwd_packets",      "fwd_packets",      FieldType::INTEGER}},
    {"rev_packets",      {FieldId::REV_PACKETS,      "rev_packets",      "rev_packets",      FieldType::INTEGER}},
    {"payload_bytes",    {FieldId::PAYLOAD_BYTES,    "payload_bytes",    "payload_bytes",    FieldType::INTEGER}},
    {"rtt_avg_us",       {FieldId::RTT_AVG_US,       "rtt_avg_us",       "avg_rtt_us",       FieldType::INTEGER}},
    {"min_rtt_us",       {FieldId::MIN_RTT_US,       "min_rtt_us",       "min_rtt_us",       FieldType::INTEGER}},
    {"retransmit_count", {FieldId::RETRANSMIT_COUNT, "retransmit_count", "retransmit_count", FieldType::INTEGER}},
    {"zero_windows",     {FieldId::ZERO_WINDOWS,     "zero_windows",     "zero_window_events", FieldType::INTEGER}},
    {"tcp_state",        {FieldId::TCP_STATE,        "tcp_state",        "tcp_state",        FieldType::INTEGER}},
    {"app_protocol",     {FieldId::APP_PROTOCOL,     "app_protocol",     "app_protocol",     FieldType::INTEGER}},
    {"tls_sni",          {FieldId::TLS_SNI,          "tls_sni",          "tls_sni",          FieldType::STRING}},
    {"http.host",        {FieldId::HTTP_HOST,        "http.host",        "http_host",        FieldType::STRING}},
    {"dns.query",        {FieldId::DNS_QUERY,        "dns.query",        "dns_query",        FieldType::STRING}},
    {"session_id",       {FieldId::SESSION_ID,       "session_id",       "session_id",       FieldType::STRING}},
    {"tags",             {FieldId::TAGS,             "tags",             "tags",             FieldType::STRING}}
};

std::optional<FieldMeta> FieldRegistry::get_field(const std::string& name) {
    auto it = REGISTRY.find(name);
    if (it != REGISTRY.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool FieldRegistry::is_valid_operator_for_type(FieldType type, const std::string& op) {
    if (type == FieldType::STRING) {
        return op == "=" || op == "!=" || op == ":" || op == "~/";
    }
    if (type == FieldType::IP) {
        return op == "=" || op == "!=" || op == "IN" || op == "<<"; // << is CIDR contained by
    }
    // numeric / timestamp / port
    return op == "=" || op == "!=" || op == ">" || op == ">=" || op == "<" || op == "<=";
}

} // namespace query
} // namespace search
