#pragma once

#include "../planner/query_planner.hpp"
#include "../../storage/pg_connection_pool.hpp"
#include <memory>
#include <nlohmann/json.hpp>

namespace search {
namespace executor {

class SearchExecutor {
public:
    SearchExecutor(PgConnectionPool& pool);

    nlohmann::json execute(const planner::SqlPlan& plan);

private:
    PgConnectionPool& pool_;
};

} // namespace executor
} // namespace search
