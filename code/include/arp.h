#ifndef ARP_H_
#define ARP_H_
#include "DEBUG.h"
#include "device.h"
#include "ip.h"

namespace arp {
extern std::map<const ip_addr, const std::string, compare_ip> arp_map;
extern std::mutex condition_mutex;
extern uint8_t cond;
std::string findMAC(Device* dev_ptr, ip_addr target_ip);
void sendARPRequest(Device* dev_ptr, ip_addr target_ip);
void handleARPReply(const void* buf, int len, std::string& targetMAC);
struct arpPacket {
    arphdr header;
    u_char srcMac[6];
    ip_addr srcIP;
    u_char dstMac[6];
    ip_addr dstIP;
    arpPacket(const void* buf); // when init, it will change byte order
    arpPacket();
    void change_to_net_order();
    void change_back();
};
void handleARPRequest(Device* dev_ptr, arpPacket& pckt);
}
#endif