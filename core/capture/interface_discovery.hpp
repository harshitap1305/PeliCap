#pragma once
#include <vector>
#include <string>

struct InterfaceInfo {
    std::string name;
    std::string description;
    std::string ip_address;
    std::string mac_address;
    bool is_loopback;
};

std::vector<InterfaceInfo> list_interfaces();
