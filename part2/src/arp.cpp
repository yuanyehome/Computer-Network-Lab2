#include "arp.h"

namespace arp {
    std::map<const ip_addr, const std::string, compare_ip> arp_map;
}

std::string arp::findMAC(Device* dev_ptr, ip_addr target_ip)
{
    if (arp_map.find(target_ip) != arp_map.end()) {
        return arp_map.at(target_ip);
    } else {
        sendARPRequest(dev_ptr, target_ip);
        return "";
    }
}

void arp::sendARPRequest(Device* dev_ptr, ip_addr target_ip)
{
    u_char* char_mac = new u_char[6];
    memset(char_mac, 0xff, 6);
    dev_ptr->sendFrame(NULL, 0, ETHERTYPE_ARP, char_mac);
    delete[] char_mac;
}