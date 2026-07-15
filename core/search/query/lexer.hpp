#pragma once

#include "token.hpp"
#include <vector>
#include <string>
#include <stdexcept>

namespace search {
namespace query {

class LexerError : public std::runtime_error {
public:
    LexerError(const std::string& msg, size_t pos) 
        : std::runtime_error(msg), position(pos) {}
    size_t position;
};

class Lexer {
public:
    Lexer(const std::string& query);
    
    // Parses the entire query string and returns a list of tokens
    std::vector<Token> tokenize();

private:
    std::string input_;
    size_t pos_;
    size_t len_;

    char peek(size_t offset = 0) const;
    char advance();
    bool is_at_end() const;
    void skip_whitespace();

    Token scan_word();
    Token scan_string();
    Token scan_number_or_ip();
    Token scan_operator();
    Token scan_regex();
};

} // namespace query
} // namespace search
