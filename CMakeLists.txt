cmake_minimum_required(VERSION 3.20)
project(PaliCap CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(Drogon CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS lockfree)
find_package(absl CONFIG REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(libpqxx CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)

add_executable(palicap
    core/capture/interface_discovery.cpp
    core/capture/capture_session.cpp
    core/capture/pcap_loader.cpp
    core/dissector/dissector_engine.cpp
    core/flow/flow_engine.cpp
    core/metrics/metrics_engine.cpp
    core/detection/detection_engine.cpp
    core/storage/storage_engine.cpp
    core/storage/pg_connection_pool.cpp
    core/storage/batch_writer.cpp
    core/storage/pcap_file_manager.cpp
    core/storage/retention/retention_manager.cpp
    core/storage/migrations/migration_runner.cpp
    core/search/query/lexer.cpp
    core/search/query/parser.cpp
    core/search/query/field_registry.cpp
    core/search/planner/query_planner.cpp
    core/search/executor/search_executor.cpp
    api/capture_api.cpp
    main.cpp
)

target_include_directories(palicap PRIVATE core api)

target_link_libraries(palicap PRIVATE
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Common++
    PcapPlusPlus::Packet++
    Drogon::Drogon
    nlohmann_json::nlohmann_json
    absl::flat_hash_map
    absl::hash
    PostgreSQL::PostgreSQL
    libpqxx::pqxx
    re2::re2
)

target_link_libraries(palicap PRIVATE Boost::lockfree)
