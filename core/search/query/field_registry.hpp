#pragma once

#include <string>
#include <unordered_map>
#include <optional>

namespace search {
namespace query {

enum class FieldId {
    // Flow/Network fields
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    PROTOCOL,
    INTERFACE_NAME,
    START_TIME,
    END_TIME,
    DURATION_MS,
    BYTES,
    PACKETS,
    FWD_BYTES,
    REV_BYTES,
    FWD_PACKETS,
    REV_PACKETS,
    
    PAYLOAD_BYTES,
    
    // TCP specific
    RTT_AVG_US,
    MIN_RTT_US,
    RETRANSMIT_COUNT,
    ZERO_WINDOWS,
    TCP_STATE,
    
    // App layer
    APP_PROTOCOL,
    TLS_SNI,
    HTTP_HOST,
    DNS_QUERY,
    
    // Alerts
    HAS_ALERT,
    
    // Meta/Session
    SESSION_ID,
    TAGS,
    
    UNKNOWN
};

enum class FieldType {
    IP,
    PORT,
    INTEGER,
    FLOAT,
    STRING,
    TIMESTAMP,
    BOOLEAN
};

struct FieldMeta {
    FieldId id;
    std::string name;        // e.g. "src_ip"
    std::string db_column;   // e.g. "src_ip"
    FieldType type;
};

class FieldRegistry {
public:
    static std::optional<FieldMeta> get_field(const std::string& name);
    static bool is_valid_operator_for_type(FieldType type, const std::string& op);
};

} // namespace query
} // namespace search
