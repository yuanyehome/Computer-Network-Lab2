#include "DEBUG.h"
#include "device.h"
#include "ip.h"

namespace arp {
std::map<const ip_addr, const std::string, compare_ip> arp_map;
std::string findMAC(Device* dev_ptr, ip_addr target_ip)
{
    if (arp_map.find(target_ip) != arp_map.end()) {
        return arp_map.at(target_ip);
    } else {
        auto dstMAC = sendARPRequest(dev_ptr, target_ip);
        return dstMAC;
    }
}
std::string sendARPRequest(Device* dev_ptr, ip_addr target_ip)
{
    return "Not implemented";
}
}