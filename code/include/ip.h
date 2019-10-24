#ifndef IP_H_
#define IP_H_
#include "DEBUG.h"

namespace IP {
extern IPPacketReceiveCallback IPCallback;
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
int setRoutingTable(const struct in_addr dest, const struct in_addr mask,
    const void* nextHopMAC, const char* device);
struct packet {
    ip header;
    const u_char* payload;
    packet()
    {
        header.ip_v = 4;
        header.ip_hl = 5;
        header.ip_tos = 0;
        header.ip_id = 0;
        header.ip_off = IP_DF;
        header.ip_ttl = 16;
    }
    void change_to_net_byte_order();
    void change_back();
};
};
std::string IPtoStr(ip_addr IP)
{
    char ip[30];
    snprintf(ip, 4, "%d:%d:%d:%d", IP.s_addr >> 24, (IP.s_addr >> 16) & 255, (IP.s_addr >> 8) & 255, IP.s_addr & 255);
    return std::string(ip);
}

struct compare_ip {
    bool operator()(const ip_addr ip1, const ip_addr ip2) const;
};

bool in_same_subnet(ip_addr ip1, ip_addr ip2, ip_addr mask);

/*
 * Internet Datagram Header
 *  0               1               2               3              |
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#endif