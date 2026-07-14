#pragma once
#include "../pg_connection_pool.hpp"
#include <string>
#include <vector>

namespace storage {

class MigrationRunner {
public:
    explicit MigrationRunner(PgConnectionPool& pool);
    
    // Runs all pending migrations. Returns true if successful.
    bool run_all();

private:
    struct Migration {
        int version;
        std::string description;
        std::string sql;
    };

    void ensure_migrations_table(pqxx::connection& conn);
    int get_current_version(pqxx::connection& conn);
    void apply_migration(pqxx::connection& conn, const Migration& m);

    PgConnectionPool& pool_;
    std::vector<Migration> migrations_;
};

} // namespace storage
