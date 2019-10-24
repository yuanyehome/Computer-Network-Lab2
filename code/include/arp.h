#ifndef ARP_H_
#define ARP_H_
#include "DEBUG.h"
#include "device.h"
#include "ip.h"

namespace arp {
extern std::map<const ip_addr, const std::string, compare_ip> arp_map;
std::string findMAC(Device* dev_ptr, ip_addr target_ip);
void sendARPRequest(Device* dev_ptr, ip_addr target_ip);
void sendARPReply(Device* dev_ptr, std::string& dstMac);
void handleAPRReply(const void* buf, int len);
}
#endif