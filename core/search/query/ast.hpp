#pragma once

#include "field_registry.hpp"
#include <string>
#include <vector>
#include <memory>
#include <variant>
#include <cstdint>

namespace search {
namespace query {

enum class AstNodeType {
    AND,
    OR,
    NOT,
    FILTER
};

class AstNode {
public:
    virtual ~AstNode() = default;
    virtual AstNodeType get_type() const = 0;
};

using AstNodePtr = std::shared_ptr<AstNode>;

class AndNode : public AstNode {
public:
    std::vector<AstNodePtr> children;
    AstNodeType get_type() const override { return AstNodeType::AND; }
};

class OrNode : public AstNode {
public:
    std::vector<AstNodePtr> children;
    AstNodeType get_type() const override { return AstNodeType::OR; }
};

class NotNode : public AstNode {
public:
    AstNodePtr child;
    AstNodeType get_type() const override { return AstNodeType::NOT; }
};

// Represents a value in a filter (e.g. 10.0.0.1, 443, "google.com")
using FilterValue = std::variant<std::string, double, uint32_t, std::pair<std::string, uint8_t>>;

class FilterNode : public AstNode {
public:
    FieldMeta field;
    std::string op; // "=", "!=", ">", "<", ":", "~/"
    FilterValue value;
    
    AstNodeType get_type() const override { return AstNodeType::FILTER; }
};

} // namespace query
} // namespace search
