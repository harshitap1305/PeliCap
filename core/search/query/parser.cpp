#include "parser.hpp"

namespace search {
namespace query {

Parser::Parser(const std::vector<Token>& tokens) : tokens_(tokens), pos_(0) {}

const Token& Parser::peek() const {
    return tokens_[pos_];
}

const Token& Parser::advance() {
    if (!is_at_end()) pos_++;
    return tokens_[pos_ - 1];
}

bool Parser::is_at_end() const {
    return peek().type == TokenType::END_OF_FILE;
}

bool Parser::match(TokenType type) {
    if (peek().type == type) {
        advance();
        return true;
    }
    return false;
}

const Token& Parser::consume(TokenType type, const std::string& err_msg) {
    if (peek().type == type) return advance();
    throw ParseError(err_msg, peek().position);
}

AstNodePtr Parser::parse() {
    if (is_at_end()) return nullptr;
    auto node = parse_or_expr();
    if (!is_at_end()) {
        throw ParseError("Unexpected token at end of query", peek().position);
    }
    return node;
}

AstNodePtr Parser::parse_or_expr() {
    auto node = parse_and_expr();
    
    while (match(TokenType::BOOL_OR)) {
        auto right = parse_and_expr();
        auto or_node = std::make_shared<OrNode>();
        or_node->children.push_back(node);
        or_node->children.push_back(right);
        
        // Flatten ORs
        while (match(TokenType::BOOL_OR)) {
            or_node->children.push_back(parse_and_expr());
        }
        node = or_node;
    }
    return node;
}

AstNodePtr Parser::parse_and_expr() {
    auto node = parse_not_expr();
    
    // AND is optional between terms. 
    // If the next token is not an operator or closing paren/EOF, it's an implicit AND.
    while (true) {
        if (match(TokenType::BOOL_AND)) {
            auto right = parse_not_expr();
            auto and_node = std::make_shared<AndNode>();
            and_node->children.push_back(node);
            and_node->children.push_back(right);
            node = and_node;
        } else if (!is_at_end() && peek().type != TokenType::BOOL_OR && peek().type != TokenType::RPAREN) {
            // Implicit AND
            auto right = parse_not_expr();
            auto and_node = std::make_shared<AndNode>();
            if (node->get_type() == AstNodeType::AND) {
                auto existing_and = std::static_pointer_cast<AndNode>(node);
                existing_and->children.push_back(right);
            } else {
                and_node->children.push_back(node);
                and_node->children.push_back(right);
                node = and_node;
            }
        } else {
            break;
        }
    }
    
    return node;
}

AstNodePtr Parser::parse_not_expr() {
    if (match(TokenType::BOOL_NOT)) {
        auto not_node = std::make_shared<NotNode>();
        not_node->child = parse_not_expr();
        return not_node;
    }
    return parse_primary();
}

AstNodePtr Parser::parse_primary() {
    if (match(TokenType::LPAREN)) {
        auto node = parse_or_expr();
        consume(TokenType::RPAREN, "Expect ')' after expression.");
        return node;
    }
    return parse_filter();
}

AstNodePtr Parser::parse_filter() {
    Token field_tok = consume(TokenType::FIELD_NAME, "Expect field name.");
    
    auto field_meta = FieldRegistry::get_field(field_tok.value);
    
    // For alias shorthands (like 'ip' expanding to 'src_ip OR dst_ip'), 
    // we would handle that here by returning an OrNode.
    // Let's implement the basic single field filter first.
    
    if (!field_meta) {
        // If it's not a valid field, it might be a free-text search macro like "google" 
        // which expands to `host:google`. But we stick to explicit fields for now.
        throw ParseError("Unknown field: " + field_tok.value, field_tok.position);
    }

    std::string op;
    if (match(TokenType::COLON)) op = ":";
    else if (match(TokenType::OPERATOR_EQ)) op = "=";
    else if (match(TokenType::OPERATOR_NEQ)) op = "!=";
    else if (match(TokenType::OPERATOR_GT)) op = ">";
    else if (match(TokenType::OPERATOR_GTE)) op = ">=";
    else if (match(TokenType::OPERATOR_LT)) op = "<";
    else if (match(TokenType::OPERATOR_LTE)) op = "<=";
    else if (match(TokenType::OPERATOR_CONTAINS)) op = ":";
    else if (match(TokenType::OPERATOR_REGEX)) op = "~/";
    else {
        throw ParseError("Expect operator after field name.", peek().position);
    }
    
    if (!FieldRegistry::is_valid_operator_for_type(field_meta->type, op)) {
        throw ParseError("Invalid operator '" + op + "' for field type.", field_tok.position);
    }

    auto filter_node = std::make_shared<FilterNode>();
    filter_node->field = *field_meta;
    filter_node->op = op;
    
    Token val_tok = advance();
    if (val_tok.type == TokenType::STRING_VALUE || val_tok.type == TokenType::FIELD_NAME) {
        filter_node->value = val_tok.value;
    } else if (val_tok.type == TokenType::NUMBER_VALUE) {
        if (field_meta->type == FieldType::INTEGER || field_meta->type == FieldType::PORT) {
            filter_node->value = static_cast<uint32_t>(val_tok.num_val);
        } else {
            filter_node->value = val_tok.num_val;
        }
    } else if (val_tok.type == TokenType::IP_VALUE) {
        filter_node->value = val_tok.value; // Store IP as string
    } else if (val_tok.type == TokenType::CIDR_VALUE) {
        filter_node->value = std::pair<std::string, uint8_t>(val_tok.value, val_tok.cidr_prefix);
    } else if (val_tok.type == TokenType::OPERATOR_REGEX) {
        filter_node->value = val_tok.value;
    } else {
        throw ParseError("Expect value after operator.", val_tok.position);
    }
    
    return filter_node;
}

} // namespace query
} // namespace search
