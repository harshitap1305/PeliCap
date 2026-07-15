#pragma once

#include "../query/ast.hpp"
#include <string>
#include <vector>
#include <variant>
#include <memory>
#include <pqxx/pqxx>

namespace search {
namespace planner {

// Holds the resulting SQL string and the ordered parameter bindings.
struct SqlPlan {
    std::string sql;
    // We store values as strings (pqxx::to_string handles conversions)
    // to pass easily to pqxx::params dynamically.
    std::vector<std::string> params;
    
    // Extracted session ID (if specified) to help Executor optimize
    std::string session_id;
};

class QueryPlanner {
public:
    QueryPlanner();

    // Generates a complete SELECT statement with WHERE clause from AST.
    SqlPlan plan_flows_query(const search::query::AstNodePtr& ast, 
                             const std::string& session_id,
                             int limit = 50, 
                             int offset = 0);

private:
    std::string visit(const search::query::AstNodePtr& node, SqlPlan& plan);
    std::string visit_and(const std::shared_ptr<search::query::AndNode>& node, SqlPlan& plan);
    std::string visit_or(const std::shared_ptr<search::query::OrNode>& node, SqlPlan& plan);
    std::string visit_not(const std::shared_ptr<search::query::NotNode>& node, SqlPlan& plan);
    std::string visit_filter(const std::shared_ptr<search::query::FilterNode>& node, SqlPlan& plan);
};

} // namespace planner
} // namespace search
