cmake_minimum_required(VERSION 3.20)
project(PaliCap CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(PcapPlusPlus CONFIG REQUIRED)
find_package(Drogon CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(Boost REQUIRED)
find_package(absl CONFIG REQUIRED)

add_executable(palicap
    core/capture/interface_discovery.cpp
    core/capture/capture_session.cpp
    core/capture/pcap_loader.cpp
    core/dissector/dissector_engine.cpp
    core/flow/flow_engine.cpp
    core/metrics/metrics_engine.cpp
    api/capture_api.cpp
    main.cpp
)

target_include_directories(palicap PRIVATE core)

target_link_libraries(palicap PRIVATE
    PcapPlusPlus::Pcap++
    PcapPlusPlus::Common++
    PcapPlusPlus::Packet++
    Drogon::Drogon
    nlohmann_json::nlohmann_json
    absl::flat_hash_map
    absl::hash
)

if(TARGET Boost::headers)
    target_link_libraries(palicap PRIVATE Boost::headers)
else()
    target_include_directories(palicap PRIVATE ${Boost_INCLUDE_DIRS})
endif()
