#include "routeTable.h"

namespace Router {
router router_mgr;
std::mutex table_mutex;
}

Router::routerItem::routerItem(const ip_addr& ip_prefix_, const ip_addr& subnetMask_, Device* dev_ptr_, const std::string& next_hop_, const int _dist)
    : dev_ptr(dev_ptr_)
    , netx_hop(next_hop_)
    , dist(_dist)
{
    ip_prefix.s_addr = ip_prefix_.s_addr;
    subnetMask.s_addr = subnetMask_.s_addr;
};

void myListenFunc()
{
    Router::table_mutex.lock();
    Router::router_mgr.printTable();
    Router::router_mgr.check();
    Router::router_mgr.reset();
    Router::table_mutex.unlock();
    sleep(ROUTE_OFFLINE_TIME);
}

void Router::router::printTable()
{
    dbg_printf("\033[32m[INFO]\033[0m [Print Routing Table]\n");
    dbg_printf("\033[32m[Neighbor]\033[0m");
    for (auto& item : neighbor_mac) {
        dbg_printf("%s", item.first.c_str());
    }
    dbg_printf("\n");
    // 待完成
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

void Router::router::initializeTable(DeviceManager& dev_mgr)
{
    dbg_printf("\033[32m[INFO]\033[0m [route table initializing]\n");
    for (auto& dev_ptr : dev_mgr.device_list) {
        ip_addr tmp_ip_prefix;
        tmp_ip_prefix.s_addr = dev_ptr->dev_ip.s_addr & dev_ptr->subnetMask.s_addr;
        ip_addr tmp_mask;
        tmp_mask.s_addr = dev_ptr->subnetMask.s_addr;
        for (auto& dev_ptr2 : dev_mgr.device_list) {
            setRoutingTable(tmp_ip_prefix, tmp_mask, dev_ptr2->mac, dev_ptr2, 0);
        }
    }
    t = std::thread(myListenFunc);
}

void Router::sendTable(const Device* dev_ptr)
{
    table_mutex.lock();
    dbg_printf("\033[32m[INFO]\033[0m [sendTable Function]\n");
    int cnt = Router::router_mgr.routetable.size();
    int total_size = cnt * sizeof(Router::itemPacket);
    int single_size = sizeof(Router::itemPacket);
    dbg_printf("\033[33m[DEBUG]\033[0m [cnt: %d] [single_size: %d] [total_size: %d]\n",
        cnt, single_size, total_size);
    u_char content[total_size + 1];
    auto iter = Router::router_mgr.routetable.begin();
    for (int i = 0; i < cnt; ++i) {
        Router::itemPacket tmp_pckt;
        tmp_pckt.dist = iter->dist;
        tmp_pckt.ip_prefix.s_addr = iter->ip_prefix.s_addr;
        tmp_pckt.subnetMask.s_addr = iter->subnetMask.s_addr;
        strToMac(iter->netx_hop, tmp_pckt.next_mac);
        memcpy((u_char*)(content + cnt * single_size), (u_char*)&tmp_pckt, single_size);
        ++iter;
    }
    uint8_t dstMac[6] = { 255, 255, 255, 255, 255, 255 };
    dev_ptr->sendFrame((void*)content, total_size, MY_ROUTE_PROTO, (void*)dstMac);
    table_mutex.unlock();
    sleep(ROUTE_INTERVAL);
} // 序列化

bool Router::routerItem::contain_ip(const ip_addr& dst_ip) const
{
    return ((dst_ip.s_addr & subnetMask.s_addr) == ip_prefix.s_addr);
}
bool Router::routerItem::operator<(const routerItem& item) const
{
    if (subnetMask.s_addr < item.subnetMask.s_addr)
        return true;
    else if (subnetMask.s_addr > item.subnetMask.s_addr)
        return false;
    else
        return (ip_prefix.s_addr < item.ip_prefix.s_addr);
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
        table_mutex.lock();
        routetable.insert(routerItem(ip_prefix, mask, device, nextHopMAC, dist));
        table_mutex.unlock();
    } catch (const char* err_msg) {
        dbg_printf("033[31m[ERROR] [%s]\n", err_msg);
        return -1;
    }
    return 0;
}

void Router::router::handleReceiveRouteTable(const std::string& srcMac, const u_char* content, const int len, Device* dev_ptr)
{
    table_mutex.lock();
    // 加入邻居
    Router::router_mgr.neighbor_mac[srcMac] = true;
    // 合并路由表
    assert(len % sizeof(Router::itemPacket) == 0);
    int single_size = sizeof(Router::itemPacket);
    int cnt = len / single_size;
    Router::itemPacket neighbor_table[cnt];
    for (int i = 0; i < cnt; ++i) {
        memcpy(neighbor_table + i, content + single_size * i, single_size);
        ++neighbor_table[i].dist;
    }
    for (int i = 0; i < cnt; ++i) {
        ip_addr tmp_ip_prefix = neighbor_table[i].ip_prefix;
        ip_addr tmp_mask = neighbor_table[i].subnetMask;
        bool is_find = 0;
        routerItem tmp_item(neighbor_table[i].ip_prefix, neighbor_table[i].subnetMask, dev_ptr,
            srcMac, neighbor_table[i].dist);
        for (auto iter = routetable.begin(); iter != routetable.end(); ++iter) {
            if (iter->ip_prefix.s_addr == tmp_ip_prefix.s_addr
                && iter->subnetMask.s_addr == tmp_mask.s_addr) {
                is_find = 1;
                if (iter->dist > neighbor_table[i].dist) {

                    routetable.erase(iter);
                    routetable.insert(tmp_item);
                    break;
                }
            }
        }
        if (!is_find) {
            routetable.insert(tmp_item);
        }
    }
    dbg_printf("\033[32m[INFO]\033[0m [handleReceiveRouteTable]\n");
    table_mutex.unlock();
} // 反序列化；合并路由表