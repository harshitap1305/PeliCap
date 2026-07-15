#pragma once

#include <string>
#include <variant>
#include <utility>
#include <cstdint>

namespace search {
namespace query {

enum class TokenType {
    FIELD_NAME,
    COLON,
    OPERATOR_EQ,
    OPERATOR_NEQ,
    OPERATOR_GT,
    OPERATOR_GTE,
    OPERATOR_LT,
    OPERATOR_LTE,
    OPERATOR_CONTAINS, // : for text
    OPERATOR_REGEX,    // ~/
    STRING_VALUE,
    NUMBER_VALUE,
    IP_VALUE,
    CIDR_VALUE,
    BOOL_AND,
    BOOL_OR,
    BOOL_NOT,
    LPAREN,
    RPAREN,
    END_OF_FILE,
    UNKNOWN
};

struct Token {
    TokenType type;
    std::string value; // Raw string value
    size_t position;   // Character position in original query for error reporting
    
    // For specific types
    double num_val = 0.0;
    uint8_t cidr_prefix = 0;
};

std::string token_type_to_string(TokenType type);

} // namespace query
} // namespace search
