#pragma once

#include "lexer.hpp"
#include "ast.hpp"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <optional>

namespace search {
namespace query {

class ParseError : public std::runtime_error {
public:
    ParseError(const std::string& msg, size_t pos) 
        : std::runtime_error(msg), position(pos) {}
    size_t position;
};

class Parser {
public:
    Parser(const std::vector<Token>& tokens);
    
    // Parses the token stream and returns the AST root
    AstNodePtr parse();

private:
    std::vector<Token> tokens_;
    size_t pos_;

    const Token& peek() const;
    const Token& advance();
    bool is_at_end() const;
    bool match(TokenType type);
    const Token& consume(TokenType type, const std::string& err_msg);

    AstNodePtr parse_or_expr();
    AstNodePtr parse_and_expr();
    AstNodePtr parse_not_expr();
    AstNodePtr parse_primary();
    AstNodePtr parse_filter();
};

} // namespace query
} // namespace search
