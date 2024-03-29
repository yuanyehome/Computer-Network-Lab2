#ifndef ROUTETABLE_H_
#define ROUTETABLE_H_
#include "DEBUG.h"
#include "arp.h"
#include "device.h"
#include "ip.h"

namespace Router {
extern std::mutex table_mutex;
struct itemPacket {
    struct __attribute__((__packed__)) {
        ip_addr ip_prefix;
        ip_addr subnetMask;
        u_char next_mac[6];
        distance dist;
    };
};
struct routerItem {
    ip_addr ip_prefix;
    ip_addr subnetMask;
    Device* dev_ptr; // 要经由哪个device发出去
    std::string netx_hop;
    distance dist;
    routerItem(const ip_addr& ip_prefix_, const ip_addr& subnetMask_, Device* dev_ptr_, const std::string& next_hop_, const int _dist);
    bool contain_ip(const ip_addr& dst_ip) const;
    bool operator<(const routerItem& item) const;
};
struct router {
    std::set<routerItem> routetable;
    std::map<std::string, bool> neighbor_mac;
    std::string get_nexthop_mac(const ip_addr& dstIP);
    std::thread t;
    void handleReceiveRouteTable(const std::string& srcMac, const u_char* content, const int len, Device* dev_ptr);
    int setRoutingTable(const ip_addr dest, const ip_addr mask,
        const std::string& nextHopMAC, Device* device, const int dist);
    void check();
    void reset();
    void printTable();
    void deleteTableItem(const std::string& mac);
    void initializeTable(DeviceManager& dev_mgr);
    ~router();
};
void sendTable(const Device* dev_ptr);
extern router router_mgr;
}
#endif