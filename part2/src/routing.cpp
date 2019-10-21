#include "routeTable.h"

bool Router::routerItem::contain_ip(const ip_addr& dst_ip) const
{
    return ((dst_ip.s_addr & subnetMask.s_addr) == ip_prefix.s_addr);
}

std::string Router::router::get_nexthop_mac(const ip_addr& dstIP)
{
    for (auto& item : routetable) {
        if (item.contain_ip(dstIP)) {
            return item.netx_hop;
        }
    }
    throw "target IP not found in route table!";
}