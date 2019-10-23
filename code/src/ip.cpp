#include "ip.h"
#include "arp.h"
#include "device.h"
#include "routeTable.h"

namespace IP {
    IPPacketReceiveCallback IPCallback;
}

bool in_same_subnet(ip_addr ip1, ip_addr ip2, ip_addr mask)
{
    return ((ip1.s_addr & mask.s_addr) == (ip2.s_addr & mask.s_addr));
}

void IP::packet::change_to_net_byte_order()
{
    header.ip_len = htons(header.ip_len);
    header.ip_id = htons(header.ip_id);
    header.ip_off = htons(header.ip_off);
    header.ip_sum = htons(header.ip_sum);
}

void IP::packet::change_back()
{
    header.ip_len = ntohs(header.ip_len);
    header.ip_id = ntohs(header.ip_id);
    header.ip_off = ntohs(header.ip_off);
    header.ip_sum = ntohs(header.ip_sum);
}

int sendIPPacket(DeviceManager mgr,
    const struct in_addr src,
    const struct in_addr dest,
    int proto,
    const void* buf,
    int len)
{
    auto dev_ptr = mgr.findDevice(src);
    if (!dev_ptr) {
        dbg_printf("[ERROR] srcIP not found in this machine, please check your IP");
        return -1;
    }
    auto srcMac = dev_ptr->mac;
    std::string dstMAC;
    if (in_same_subnet(src, dest, dev_ptr->subnetMask)) {
        dstMAC = arp::findMAC(dev_ptr, dest);
    } else {
        try {
            dstMAC = Router::router_mgr.get_nexthop_mac(dest);
        } catch (const char* e) {
            dbg_printf("[ERROR] %s [IP]=%s\n", e, inet_ntoa(dest));
            return -1;
        }
    }
    IP::packet pckt;
    pckt.header.ip_src = src;
    pckt.header.ip_dst = dest;
    pckt.header.ip_p = proto;
    pckt.payload = (const u_char*)buf;
    int total_len = pckt.header.ip_hl + len;
    pckt.header.ip_len = total_len;
    pckt.change_to_net_byte_order();
    u_char* IPpacket_final = new u_char[len];
    u_char* char_mac = new u_char[6];
    strToMac(dstMAC, char_mac);
    memcpy(IPpacket_final, &pckt.header, pckt.header.ip_hl);
    memcpy(IPpacket_final, pckt.payload, len);
    dev_ptr->sendFrame(IPpacket_final, total_len, ETHERTYPE_IP, char_mac);
    delete[] char_mac;
    delete[] IPpacket_final;
    return 0;
}

int IP::setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    dbg_printf("[INFO] [Function] [setIPPacketReceiveCallback]************");
    try {
        IPCallback = callback;
    } catch (const char* err_msg) {
        dbg_printf("[Error] [Function] [setIPPacketReceiveCallback] %s\n", err_msg);
        return -1;
    }
    return 0;
}

bool compare_ip::operator()(ip_addr ip1, ip_addr ip2) const
{
    return ip1.s_addr < ip2.s_addr;
}