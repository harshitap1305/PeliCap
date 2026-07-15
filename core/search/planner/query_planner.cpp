#include "query_planner.hpp"
#include <sstream>
#include <stdexcept>
#include <iostream>

namespace search {
namespace planner {

QueryPlanner::QueryPlanner() {}

SqlPlan QueryPlanner::plan_flows_query(const search::query::AstNodePtr& ast, 
                                       const std::string& session_id,
                                       int limit, 
                                       int offset) {
    SqlPlan plan;
    plan.session_id = session_id;
    
    std::string where_clause = visit(ast, plan);
    
    // Always enforce session_id boundary for partitioning/performance!
    if (!session_id.empty()) {
        plan.params.push_back(session_id);
        std::string session_cond = "session_id = $" + std::to_string(plan.params.size());
        
        if (where_clause.empty()) {
            where_clause = session_cond;
        } else {
            where_clause = "(" + where_clause + ") AND " + session_cond;
        }
    }
    
    std::string sql = "SELECT * FROM flows ";
    if (!where_clause.empty()) {
        sql += "WHERE " + where_clause + " ";
    }
    sql += "ORDER BY start_time DESC ";
    
    if (limit > 0) {
        sql += "LIMIT " + std::to_string(limit) + " ";
    }
    if (offset > 0) {
        sql += "OFFSET " + std::to_string(offset);
    }
    
    plan.sql = sql;
    return plan;
}

std::string QueryPlanner::visit(const search::query::AstNodePtr& node, SqlPlan& plan) {
    if (!node) return "";
    
    switch (node->get_type()) {
        case search::query::AstNodeType::AND:
            return visit_and(std::static_pointer_cast<search::query::AndNode>(node), plan);
        case search::query::AstNodeType::OR:
            return visit_or(std::static_pointer_cast<search::query::OrNode>(node), plan);
        case search::query::AstNodeType::NOT:
            return visit_not(std::static_pointer_cast<search::query::NotNode>(node), plan);
        case search::query::AstNodeType::FILTER:
            return visit_filter(std::static_pointer_cast<search::query::FilterNode>(node), plan);
    }
    return "";
}

std::string QueryPlanner::visit_and(const std::shared_ptr<search::query::AndNode>& node, SqlPlan& plan) {
    if (node->children.empty()) return "";
    if (node->children.size() == 1) return visit(node->children[0], plan);
    
    std::vector<std::string> parts;
    for (const auto& child : node->children) {
        std::string part = visit(child, plan);
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    
    if (parts.empty()) return "";
    if (parts.size() == 1) return parts[0];
    
    std::string result = "(";
    for (size_t i = 0; i < parts.size(); ++i) {
        result += parts[i];
        if (i < parts.size() - 1) result += " AND ";
    }
    result += ")";
    return result;
}

std::string QueryPlanner::visit_or(const std::shared_ptr<search::query::OrNode>& node, SqlPlan& plan) {
    if (node->children.empty()) return "";
    if (node->children.size() == 1) return visit(node->children[0], plan);
    
    std::vector<std::string> parts;
    for (const auto& child : node->children) {
        std::string part = visit(child, plan);
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    
    if (parts.empty()) return "";
    if (parts.size() == 1) return parts[0];
    
    std::string result = "(";
    for (size_t i = 0; i < parts.size(); ++i) {
        result += parts[i];
        if (i < parts.size() - 1) result += " OR ";
    }
    result += ")";
    return result;
}

std::string QueryPlanner::visit_not(const std::shared_ptr<search::query::NotNode>& node, SqlPlan& plan) {
    std::string child_sql = visit(node->child, plan);
    if (child_sql.empty()) return "";
    return "NOT (" + child_sql + ")";
}

std::string QueryPlanner::visit_filter(const std::shared_ptr<search::query::FilterNode>& node, SqlPlan& plan) {
    std::string col = node->field.db_column;
    std::string op = node->op;
    
    std::string val_str;
    if (std::holds_alternative<std::string>(node->value)) {
        val_str = std::get<std::string>(node->value);
    } else if (std::holds_alternative<uint32_t>(node->value)) {
        val_str = std::to_string(std::get<uint32_t>(node->value));
    } else if (std::holds_alternative<double>(node->value)) {
        val_str = std::to_string(std::get<double>(node->value));
    } else if (std::holds_alternative<std::pair<std::string, uint8_t>>(node->value)) {
        auto pair = std::get<std::pair<std::string, uint8_t>>(node->value);
        val_str = pair.first + "/" + std::to_string(pair.second);
    }

    std::string sql_op;
    
    // IP type operators
    if (node->field.type == search::query::FieldType::IP) {
        if (op == "=" || op == ":") {
            sql_op = "<<="; // Contained within or equals (subnet or exact)
        } else if (op == "!=") {
            sql_op = "!="; // Or maybe "NOT <<=" depending on exact semantics, but != works for exact inequality
        }
    }
    // String type operators
    else if (node->field.type == search::query::FieldType::STRING) {
        if (op == "=") {
            sql_op = "=";
        } else if (op == "!=") {
            sql_op = "!=";
        } else if (op == ":") {
            sql_op = "ILIKE";
            val_str = "%" + val_str + "%"; // wildcard for substring match
        } else if (op == "~/") {
            sql_op = "~*"; // case-insensitive posix regex
        }
    }
    // Numeric operators
    else {
        if (op == ":") sql_op = "=";
        else sql_op = op; // =, !=, >, >=, <, <=
    }

    plan.params.push_back(val_str);
    std::string param_idx = "$" + std::to_string(plan.params.size());
    
    // Cast if necessary
    std::string cast = "";
    if (node->field.type == search::query::FieldType::IP) {
        cast = "::inet";
    }

    return col + " " + sql_op + " " + param_idx + cast;
}

} // namespace planner
} // namespace search
