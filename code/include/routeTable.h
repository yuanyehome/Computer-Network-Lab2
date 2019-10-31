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
    routerItem(const ip_addr& ip_prefix_, const ip_addr& subnetMask_, Device* dev_ptr_, const std::string& next_hop_, const int _dist)
        : ip_prefix(ip_prefix_)
        , subnetMask(subnetMask_)
        , dev_ptr(dev_ptr_)
        , netx_hop(next_hop_)
        , dist(_dist){};
    bool contain_ip(const ip_addr& dst_ip) const;
    bool operator<(const routerItem& item) const;
};
struct router {
    std::set<routerItem> routetable;
    std::map<std::string, bool> neighbor_mac;
    std::string get_nexthop_mac(const ip_addr& dstIP);
    std::thread t;
    void handleReceiveRouteTable(const std::string& srcMac, const u_char* content, const int len);
    int setRoutingTable(const ip_addr dest, const ip_addr mask,
        const std::string& nextHopMAC, Device* device, const int dist);
    void check();
    void reset();
    void printTable();
    void deleteTableItem(const std::string& mac);
    router(); // 启动一个监听线程，监听邻居是否在线
    ~router();
};
void sendTable(const Device* dev_ptr);
extern router router_mgr;
}
#endif