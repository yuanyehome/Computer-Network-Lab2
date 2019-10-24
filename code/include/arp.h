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
void sendARPReply(Device* dev_ptr, std::string& dstMac, const ip_addr reqIP);
void handleARPReply(const void* buf, int len, std::string& targetMAC);
}
#endif