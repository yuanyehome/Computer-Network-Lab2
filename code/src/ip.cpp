#include "tcp.h"

namespace IP {
IPPacketReceiveCallback IPCallback;
}

uint16_t getChecksum(const void* vdata, size_t length)
{
    // Cast the data pointer to one that can be indexed.
    char* data = (char*)vdata;

    // Initialise the accumulator.
    uint64_t acc = 0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset = ((uintptr_t)data) & 3;
    if (offset) {
        size_t count = 4 - offset;
        if (count > length)
            count = length;
        uint32_t word = 0;
        memcpy(offset + (char*)&word, data, count);
        acc += ntohl(word);
        data += count;
        length -= count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end = data + (length & ~3);
    while (data != data_end) {
        uint32_t word;
        memcpy(&word, data, 4);
        acc += ntohl(word);
        data += 4;
    }
    length &= 3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word = 0;
        memcpy(&word, data, length);
        acc += ntohl(word);
    }

    // Handle deferred carries.
    acc = (acc & 0xffffffff) + (acc >> 32);
    while (acc >> 16) {
        acc = (acc & 0xffff) + (acc >> 16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset & 1) {
        acc = ((acc & 0xff00) >> 8) | ((acc & 0x00ff) << 8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

DeviceManager manager;
// buf and len are both a whole IP packet
int IP::myIPCallback(const void* buf, const int len)
{
    // len是包括header的
    try {
        packet pckt;
        pckt.header = *(ip*)buf;
        if (getChecksum(&pckt.header, pckt.header.ip_hl << 2) != 0) {
            dbg_printf("\033[31m[IP] [CHECKSUM ERROR]\033[0m\n");
            return -1;
        }
        dbg_printf("\033[32m[IP] [CHECKSUM SUCCESS]\033[0m\n");
        pckt.change_back();
        pckt.payload = (u_char*)buf + 20;
        assert(len > 20);
        dbg_printf("\033[32m[INFO]\033[0m [myIPCallback] [srcIP: %s] [dstIP: %s] [len: %d]\n",
            IPtoStr(pckt.header.ip_src).c_str(), IPtoStr(pckt.header.ip_dst).c_str(), len);
        dbg_printf("\033[32m[INFO]\033[0m [received an IP packet]\n\033[32m[Content]\033[0m:\n");
        for (int i = 0; i < len - 20; ++i) {
            dbg_printf("%02x ", pckt.payload[i]);
        }
        dbg_printf("\n");
        if (findHostIP(pckt.header.ip_dst)) {
            dbg_printf("\033[32m[INFO]\033[0m This is me! \n");
            TCP_handler(pckt, len - 20);
        } else {
            dbg_printf("\033[32m[INFO] [Forwarding]\033[0m\n");
            sendIPPacket(manager, pckt.header.ip_src, pckt.header.ip_dst, IPPROTO_UDP, pckt.payload, len - 20);
        }
    } catch (const char* err_msg) {
        dbg_printf("\033[31m[ERROR]\033[0m [myIPCallback] %s", err_msg);
        return -1;
    }
    return 0;
}

bool IP::findHostIP(ip_addr& dst)
{
    for (auto& item : manager.device_list) {
        // dbg_printf("[DEBUG] %s %s\n", IPtoStr(item->dev_ip).c_str(), (src.s_addr == item->dev_ip.s_addr));
        if (dst.s_addr == item->dev_ip.s_addr)
            return true;
    }
    return false;
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

std::string IPtoStr(ip_addr IP)
{
    char ip[30] = { 0 };
    snprintf(ip, 30, "%d.%d.%d.%d", IP.s_addr & 255, (IP.s_addr >> 8) & 255, (IP.s_addr >> 16) & 255, IP.s_addr >> 24);
    return std::string(ip);
}
int sendIPPacket(DeviceManager& mgr,
    const struct in_addr src,
    const struct in_addr dest,
    int proto,
    const void* buf,
    int len)
{
    dbg_printf("\033[32m[INFO]\033[0m [sendIPPacket] [srcIP: %s] [dstIP: %s]\n",
        IPtoStr(src).c_str(), IPtoStr(dest).c_str());
    auto dev_ptr = mgr.findDevice(src, dest);
    if (!dev_ptr) {
        dbg_printf("\033[31m[ERROR]\033[0m srcIP not found in this machine, please check your IP\n");
        return -1;
    }
    auto srcMac = dev_ptr->mac;
    std::string dstMAC;
    if (in_same_subnet(dev_ptr->dev_ip, dest, dev_ptr->subnetMask)) {
        dbg_printf("\033[32m[INFO]\033[0m [is_same_subnet] [srcIP: %s] [dstIP: %s]\n",
            IPtoStr(dev_ptr->dev_ip).c_str(), IPtoStr(dest).c_str());
        try {
            dstMAC = arp::findMAC(dev_ptr, dest);
        } catch (const char* err_msg) {
            dbg_printf("\033[31m[ERROR]\033[0m %s [IP]=%s\n", err_msg, inet_ntoa(dest));
            return -1;
        }
    } else {
        try {
            dstMAC = Router::router_mgr.get_nexthop_mac(dest);
        } catch (const char* e) {
            dbg_printf("\033[31m[ERROR]\033[0m %s [IP]=%s\n", e, inet_ntoa(dest));
            return -1;
        }
    }
    IP::packet pckt;
    pckt.header.ip_src = src;
    pckt.header.ip_dst = dest;
    pckt.header.ip_p = proto;
    pckt.payload = (u_char*)buf;
    int total_len = (pckt.header.ip_hl << 2) + len;
    pckt.header.ip_len = total_len;
    pckt.change_to_net_byte_order();
    pckt.header.ip_sum = 0;
    pckt.header.ip_sum = getChecksum(&pckt.header, pckt.header.ip_hl << 2);
    u_char* IPpacket_final = new u_char[total_len];
    u_char* char_mac = new u_char[6];
    strToMac(dstMAC, char_mac);
    memcpy(IPpacket_final, &pckt.header, pckt.header.ip_hl << 2);
    memcpy(IPpacket_final + (pckt.header.ip_hl << 2), pckt.payload, len);
    dbg_printf("\033[32m[INFO]\033[0m [total_len: %d]", total_len);
    dev_ptr->sendFrame(IPpacket_final, total_len, ETHERTYPE_IP, char_mac);
    delete[] char_mac;
    delete[] IPpacket_final;
    return 0;
}

int IP::setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    dbg_printf("\033[32m[INFO]\033[0m [Function] [setIPPacketReceiveCallback]************\n");
    try {
        IPCallback = callback;
    } catch (const char* err_msg) {
        dbg_printf("\033[31m[ERROR]\033[0m [Function] [setIPPacketReceiveCallback] %s\n", err_msg);
        return -1;
    }
    return 0;
}

bool compare_ip::operator()(ip_addr ip1, ip_addr ip2) const
{
    return ip1.s_addr < ip2.s_addr;
}

void IP::startBroadcast(const DeviceManager& dev_mgr)
{
    for (auto& dev_ptr : dev_mgr.device_list) {
        dev_ptr->t_send_table = std::thread(Router::sendTable, dev_ptr);
    }
} // 需要在main里面手动开开始发包