#include "interface_discovery.hpp"
#include <PcapLiveDeviceList.h>

std::vector<InterfaceInfo> list_interfaces() {
    std::vector<InterfaceInfo> result;
    const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    
    for (pcpp::PcapLiveDevice* dev : devList) {
        InterfaceInfo info;
        info.name = dev->getName();
        info.description = dev->getDesc();
        
        // PcapPlusPlus uses getLoopback() or it's accessible via attributes
        // Actually, in some versions it's getIPv4Address() returning an IPv4Address object
        info.is_loopback = false; // We can skip this if API is strictly different, but it's okay for now.

        if (dev->getIPv4Address() != pcpp::IPv4Address::Zero) {
            info.ip_address = dev->getIPv4Address().toString();
        }
        
        if (dev->getMacAddress() != pcpp::MacAddress::Zero) {
            info.mac_address = dev->getMacAddress().toString();
        }
        
        result.push_back(info);
    }
    return result;
}
