#ifndef ROUTETABLE_H_
#define ROUTETABLE_H_
#include "DEBUG.h"
#include "arp.h"
#include "device.h"
#include "ip.h"

namespace Router {
struct routerItem {
    ip_addr ip_prefix;
    ip_addr subnetMask;
    Device* dev_ptr;
    std::string netx_hop;
    distance dist;
    routerItem(const ip_addr& ip_prefix_, const ip_addr& subnetMask_, Device* dev_ptr_, const std::string& next_hop_)
        : ip_prefix(ip_prefix_)
        , subnetMask(subnetMask_)
        , dev_ptr(dev_ptr_)
        , netx_hop(next_hop_){};
    bool contain_ip(const ip_addr& dst_ip) const;
    bool operator<(routerItem item);
};
struct router {
    std::set<routerItem> routetable;
    int setRoutingTable(const ip_addr dest, const ip_addr mask,
        const std::string& nextHopMAC, Device* device);
    std::string get_nexthop_mac(const ip_addr& dstIP);
};
extern router router_mgr;
}
#endif