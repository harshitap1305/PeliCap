#include "lexer.hpp"
#include <cctype>
#include <algorithm>

namespace search {
namespace query {

Lexer::Lexer(const std::string& query) : input_(query), pos_(0), len_(query.length()) {}

char Lexer::peek(size_t offset) const {
    if (pos_ + offset >= len_) return '\0';
    return input_[pos_ + offset];
}

char Lexer::advance() {
    if (is_at_end()) return '\0';
    return input_[pos_++];
}

bool Lexer::is_at_end() const {
    return pos_ >= len_;
}

void Lexer::skip_whitespace() {
    while (!is_at_end() && std::isspace(peek())) {
        advance();
    }
}

std::vector<Token> Lexer::tokenize() {
    std::vector<Token> tokens;
    
    while (!is_at_end()) {
        skip_whitespace();
        if (is_at_end()) break;

        char c = peek();
        size_t start_pos = pos_;

        if (c == '(') {
            advance();
            tokens.push_back({TokenType::LPAREN, "(", start_pos});
        } else if (c == ')') {
            advance();
            tokens.push_back({TokenType::RPAREN, ")", start_pos});
        } else if (c == ':') {
            advance();
            tokens.push_back({TokenType::COLON, ":", start_pos});
        } else if (c == '=' || c == '!' || c == '<' || c == '>') {
            tokens.push_back(scan_operator());
        } else if (c == '"' || c == '\'') {
            tokens.push_back(scan_string());
        } else if (c == '~' && peek(1) == '/') {
            tokens.push_back(scan_regex());
        } else if (std::isdigit(c)) {
            tokens.push_back(scan_number_or_ip());
        } else if (std::isalpha(c) || c == '_' || c == '*') {
            tokens.push_back(scan_word());
        } else {
            throw LexerError("Unexpected character: " + std::string(1, c), start_pos);
        }
    }
    
    tokens.push_back({TokenType::END_OF_FILE, "", pos_});
    return tokens;
}

Token Lexer::scan_operator() {
    size_t start_pos = pos_;
    char c = advance();
    std::string op(1, c);
    
    if (c == '!' && peek() == '=') {
        op += advance();
        return {TokenType::OPERATOR_NEQ, op, start_pos};
    } else if (c == '=' && peek() == '=') { // tolerate == as =
        op += advance();
        return {TokenType::OPERATOR_EQ, op, start_pos};
    } else if (c == '=') {
        return {TokenType::OPERATOR_EQ, op, start_pos};
    } else if (c == '<') {
        if (peek() == '=') {
            op += advance();
            return {TokenType::OPERATOR_LTE, op, start_pos};
        }
        return {TokenType::OPERATOR_LT, op, start_pos};
    } else if (c == '>') {
        if (peek() == '=') {
            op += advance();
            return {TokenType::OPERATOR_GTE, op, start_pos};
        }
        return {TokenType::OPERATOR_GT, op, start_pos};
    }
    
    throw LexerError("Invalid operator", start_pos);
}

Token Lexer::scan_regex() {
    size_t start_pos = pos_;
    advance(); // ~
    advance(); // /
    
    std::string val;
    while (!is_at_end() && peek() != '/') {
        // basic escape handling for \/
        if (peek() == '\\' && peek(1) == '/') {
            val += '/';
            advance();
            advance();
        } else {
            val += advance();
        }
    }
    
    if (is_at_end()) {
        throw LexerError("Unterminated regex literal", start_pos);
    }
    advance(); // closing /
    
    return {TokenType::OPERATOR_REGEX, val, start_pos};
}

Token Lexer::scan_string() {
    size_t start_pos = pos_;
    char quote = advance();
    std::string val;
    
    while (!is_at_end() && peek() != quote) {
        if (peek() == '\\' && !is_at_end()) {
            advance(); // skip slash
            val += advance(); // add escaped char
        } else {
            val += advance();
        }
    }
    
    if (is_at_end()) {
        throw LexerError("Unterminated string literal", start_pos);
    }
    advance(); // consume closing quote
    
    return {TokenType::STRING_VALUE, val, start_pos};
}

Token Lexer::scan_word() {
    size_t start_pos = pos_;
    std::string val;
    
    // Field names can contain dots, hyphens, underscores.
    // e.g., http.status, tls_sni, google.com
    while (!is_at_end() && (std::isalnum(peek()) || peek() == '_' || peek() == '.' || peek() == '-' || peek() == '*')) {
        val += advance();
    }
    
    // Check for boolean keywords (case insensitive)
    std::string upper_val = val;
    std::transform(upper_val.begin(), upper_val.end(), upper_val.begin(), ::toupper);
    
    if (upper_val == "AND") return {TokenType::BOOL_AND, val, start_pos};
    if (upper_val == "OR") return {TokenType::BOOL_OR, val, start_pos};
    if (upper_val == "NOT") return {TokenType::BOOL_NOT, val, start_pos};
    
    // Assume it's a FIELD_NAME or STRING_VALUE (parser decides based on context, but lexer just calls it STRING/FIELD generic)
    // Actually, in many cases like `src_ip:google.com`, `src_ip` is FIELD_NAME and `google.com` is STRING_VALUE.
    // We'll mark it as FIELD_NAME here, and parser will treat it as a value if it's on the RHS of an operator.
    return {TokenType::FIELD_NAME, val, start_pos};
}

Token Lexer::scan_number_or_ip() {
    size_t start_pos = pos_;
    std::string val;
    bool has_dot = false;
    bool has_colon = false; // IPv6
    int dot_count = 0;
    
    while (!is_at_end()) {
        char c = peek();
        if (std::isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            val += advance();
        } else if (c == '.') {
            has_dot = true;
            dot_count++;
            val += advance();
        } else if (c == ':') {
            has_colon = true;
            val += advance();
        } else {
            break; // End of number/IP
        }
    }
    
    // CIDR check
    if (!is_at_end() && peek() == '/') {
        val += advance();
        std::string prefix_str;
        while (!is_at_end() && std::isdigit(peek())) {
            prefix_str += advance();
        }
        Token t = {TokenType::CIDR_VALUE, val + prefix_str, start_pos};
        t.cidr_prefix = std::stoi(prefix_str);
        return t;
    }
    
    if (has_colon || dot_count == 3) {
        return {TokenType::IP_VALUE, val, start_pos};
    }
    
    if (has_dot) { // Float
        Token t = {TokenType::NUMBER_VALUE, val, start_pos};
        t.num_val = std::stod(val);
        return t;
    }
    
    // Integer
    Token t = {TokenType::NUMBER_VALUE, val, start_pos};
    t.num_val = std::stod(val);
    return t;
}

} // namespace query
} // namespace search
