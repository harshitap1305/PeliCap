#include "token.hpp"

namespace search {
namespace query {

std::string token_type_to_string(TokenType type) {
    switch (type) {
        case TokenType::FIELD_NAME: return "FIELD_NAME";
        case TokenType::COLON: return "COLON";
        case TokenType::OPERATOR_EQ: return "OPERATOR_EQ";
        case TokenType::OPERATOR_NEQ: return "OPERATOR_NEQ";
        case TokenType::OPERATOR_GT: return "OPERATOR_GT";
        case TokenType::OPERATOR_GTE: return "OPERATOR_GTE";
        case TokenType::OPERATOR_LT: return "OPERATOR_LT";
        case TokenType::OPERATOR_LTE: return "OPERATOR_LTE";
        case TokenType::OPERATOR_CONTAINS: return "OPERATOR_CONTAINS";
        case TokenType::OPERATOR_REGEX: return "OPERATOR_REGEX";
        case TokenType::STRING_VALUE: return "STRING_VALUE";
        case TokenType::NUMBER_VALUE: return "NUMBER_VALUE";
        case TokenType::IP_VALUE: return "IP_VALUE";
        case TokenType::CIDR_VALUE: return "CIDR_VALUE";
        case TokenType::BOOL_AND: return "BOOL_AND";
        case TokenType::BOOL_OR: return "BOOL_OR";
        case TokenType::BOOL_NOT: return "BOOL_NOT";
        case TokenType::LPAREN: return "LPAREN";
        case TokenType::RPAREN: return "RPAREN";
        case TokenType::END_OF_FILE: return "END_OF_FILE";
        case TokenType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

} // namespace query
} // namespace search
