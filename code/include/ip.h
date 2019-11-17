#ifndef IP_H_
#define IP_H_
#include "DEBUG.h"
#include "device.h"

namespace IP {
extern IPPacketReceiveCallback IPCallback;
void startBroadcast(const DeviceManager& dev_mgr);
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
int setRoutingTable(const struct in_addr dest, const struct in_addr mask,
    const void* nextHopMAC, const char* device);
int myIPCallback(const void* buf, const int len);
bool findHostIP(ip_addr& src);
uint16_t getChecksum(const void* vdata, size_t length);
struct packet {
    struct __attribute__((__packed__)) {
        ip header;
        u_char* payload;
    };
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
std::string IPtoStr(ip_addr IP);

struct compare_ip {
    bool operator()(const ip_addr ip1, const ip_addr ip2) const;
};

bool in_same_subnet(ip_addr ip1, ip_addr ip2, ip_addr mask);
int sendIPPacket(DeviceManager& mgr,
    const struct in_addr src,
    const struct in_addr dest,
    int proto,
    const void* buf,
    int len);

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