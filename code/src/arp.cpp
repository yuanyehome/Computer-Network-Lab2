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
    u_char* buf = new u_char[4];
    memcpy(buf, (u_char*)&target_ip, 4);
    dev_ptr->sendFrame(buf, 4, ETHERTYPE_ARP, char_mac);
    delete[] buf;
    delete[] char_mac;
}

void arp::sendARPReply(Device* dev_ptr, std::string& dstMac, const ip_addr srcIP)
{

    dbg_printf("[INFO] [FUNCTION] [sendARPReply] Reply an ARP Request for [IP: %s] from [MAC: %s]\n", IPtoStr(srcIP), dstMac.c_str());
    return;
}

void arp::handleAPRReply(const void* buf, int len)
{
}