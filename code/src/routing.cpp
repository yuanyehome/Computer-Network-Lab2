#include "routeTable.h"

namespace Router {
router router_mgr;
}

void myListenFunc()
{
    Router::router_mgr.check();
    sleep(ROUTE_OFFLINE_TIME);
    Router::router_mgr.reset();
}

void Router::router::check()
{
    for (auto& item : neighbor_mac) {
        if (item.second == false) {
            deleteTableItem(item.first);
        }
    }
}

void Router::router::reset()
{
    for (auto iter = neighbor_mac.begin(); iter != neighbor_mac.end(); ++iter) {
        if (iter->second == false) {
            neighbor_mac.erase(iter);
        } else {
            iter->second = false;
        }
    }
}

void Router::router::deleteTableItem(const std::string& mac)
{
    for (auto iter = routetable.begin(); iter != routetable.end(); ++iter) {
        if (iter->netx_hop == mac) {
            routetable.erase(iter);
        }
    }
}

bool Router::routerItem::contain_ip(const ip_addr& dst_ip) const
{
    return ((dst_ip.s_addr & subnetMask.s_addr) == ip_prefix.s_addr);
}
bool Router::routerItem::operator<(routerItem item)
{
    if (subnetMask.s_addr < item.subnetMask.s_addr)
        return true;
    else if (subnetMask.s_addr > item.subnetMask.s_addr)
        return false;
    else
        return (ip_prefix.s_addr < item.ip_prefix.s_addr);
}
Router::router::router()
{
    dbg_printf("\033[32m[INFO]\033[0m router initializing, creating a new thread for listening\n");
    t = std::thread(myListenFunc);
}
Router::router::~router() { t.join(); }

std::string Router::router::get_nexthop_mac(const ip_addr& dstIP)
{
    for (auto& item : routetable) {
        if (item.contain_ip(dstIP)) {
            return item.netx_hop;
        }
    }
    throw "target IP not found in route table!";
}

int Router::router::setRoutingTable(const ip_addr dest, const ip_addr mask,
    const std::string& nextHopMAC, Device* device, const int dist)
{
    try {
        ip_addr ip_prefix;
        ip_prefix.s_addr = dest.s_addr & mask.s_addr;
        routetable.insert(routerItem(ip_prefix, mask, device, nextHopMAC, dist));
    } catch (const char* err_msg) {
        dbg_printf("033[31m[ERROR] [%s]\n", err_msg);
        return -1;
    }
    return 0;
}