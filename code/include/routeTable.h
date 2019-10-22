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
    routerItem(ip_addr& ip_prefix_, ip_addr& subnetMask_, Device* dev_ptr_, std::string& next_hop_, distance dist_)
        : ip_prefix(ip_prefix_)
        , subnetMask(subnetMask_)
        , dev_ptr(dev_ptr_)
        , netx_hop(next_hop_)
        , dist(dist_){};
    bool contain_ip(const ip_addr& dst_ip) const;
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