#include "arp.h"

namespace arp {
std::map<const ip_addr, const std::string, compare_ip> arp_map;
std::mutex condition_mutex;
uint8_t cond;
}
std::string arp::findMAC(Device* dev_ptr, ip_addr target_ip)
{
    if (arp_map.find(target_ip) != arp_map.end()) {
        dbg_printf("\033[32m[INFO]\033[0m [I have found mac] [sendARPRequest] [targetIP: %s] [device_name: %s] [MAC: %s]",
            IPtoStr(target_ip).c_str(), dev_ptr->name.c_str(), arp_map.at(target_ip).c_str());
        return arp_map.at(target_ip);
    } else {
        dbg_printf("\033[32m[INFO]\033[0m [I will send an ARP] [sendARPRequest] [targetIP: %s] [device_name: %s]",
            IPtoStr(target_ip).c_str(), dev_ptr->name.c_str());
        sendARPRequest(dev_ptr, target_ip);
        dbg_printf("\033[32m[INFO]\033[0m [arp::findMAC] [sendARPRequest] [targetIP: %s] [device_name: %s]",
            IPtoStr(target_ip).c_str(), dev_ptr->name.c_str());
        double time_variable = 0;
        int retry = 0;
        cond = 1;
        while (1) {
            usleep(100000);
            condition_mutex.lock();
            if (cond == 0) {
                if (arp_map.find(target_ip) != arp_map.end()) {
                    condition_mutex.unlock();
                    return arp_map.at(target_ip);
                } else {
                    cond = 0;
                    condition_mutex.unlock();
                }
            }
            time_variable += 0.1;
            if (time_variable > MAX_ARP_WATING_TIME) {
                dbg_printf("\033[32m[INFO]\033[0m [arp::findMAC] [sendARPRequest Retrying] [targetIP: %s] [device_name: %s]",
                    IPtoStr(target_ip).c_str(), dev_ptr->name.c_str());
                sendARPRequest(dev_ptr, target_ip);
                time_variable = 0;
                retry += 1;
            }
            if (retry > MAX_ARP_RETRY) {
                condition_mutex.lock();
                if (cond == 0) {
                    if (arp_map.find(target_ip) != arp_map.end()) {
                        condition_mutex.unlock();
                        return arp_map.at(target_ip);
                    } else {
                        cond = 0;
                        condition_mutex.unlock();
                    }
                } else {
                    dbg_printf("\033[31m[ERROR]\033[0m [ARP failed] [targetIP: %s] [device_name: %s]",
                        IPtoStr(target_ip).c_str(), dev_ptr->name.c_str());
                    cond = 0;
                }
                condition_mutex.unlock();
                throw "findARP failed! Please check your IP and network connection";
            }
        }
    }
}

void arp::sendARPRequest(Device* dev_ptr, ip_addr target_ip)
{
    u_char dstMac[6];
    memset(dstMac, 0xff, 6);
    arpPacket request;
    request.header.ar_op = ARPOP_REQUEST;
    request.srcIP = dev_ptr->dev_ip;
    strToMac(dev_ptr->mac, request.srcMac);
    request.dstIP = target_ip;
    memset(request.dstMac, 0, 6);
    dev_ptr->sendFrame(&request, sizeof(request), ETHERTYPE_ARP, dstMac);
}

void arp::handleARPRequest(Device* dev_ptr, arpPacket& pckt)
{
    if (pckt.dstIP.s_addr != dev_ptr->dev_ip.s_addr)
        return;
    else {
        arpPacket reply;
        reply.header.ar_op = ARPOP_REPLY;
        reply.srcIP = pckt.dstIP;
        u_char mac[6];
        strToMac(dev_ptr->mac, mac);
        memcpy(reply.srcMac, mac, 6);
        reply.dstIP = pckt.srcIP;
        memcpy(reply.dstMac, pckt.srcMac, 6);
        reply.change_to_net_order();
        dev_ptr->sendFrame(&reply, sizeof(reply), ETHERTYPE_ARP, pckt.srcMac);
    }
}

void arp::handleARPReply(const void* buf, int len, std::string& targetMAC)
{
    dbg_printf("\033[32m[INFO]\033[0m [handleARPReply]");
    arpPacket pckt(buf);
    ip_addr targetIP = pckt.srcIP;
    std::string pckt_targetMAC = MacToString(pckt.srcMac);
    dbg_printf("\033[32m[INFO]\033[0m [COMPARE] [eth_hdr_srcmac: %s] [arp_hdr_srcmac: %s]", pckt_targetMAC.c_str(), targetMAC.c_str());
    assert(targetMAC == pckt_targetMAC);
    assert(arp_map.find(targetIP) == arp_map.end());
    condition_mutex.lock();
    arp_map.insert(std::make_pair(targetIP, targetMAC));
    cond = 0;
    condition_mutex.unlock();
}

arp::arpPacket::arpPacket(const void* buf)
{
    memcpy(this, buf, sizeof(arpPacket));
    this->change_back();
}

arp::arpPacket::arpPacket()
{
    header.ar_hrd = ARPHRD_ETHER;
    header.ar_pro = ETHERTYPE_IP;
    header.ar_hln = ETHER_ADDR_LEN;
    header.ar_pln = 4;
}

void arp::arpPacket::change_to_net_order()
{
    header.ar_hrd = htons(header.ar_hrd);
    header.ar_pro = htons(header.ar_pro);
    header.ar_op = htons(header.ar_op);
}

void arp::arpPacket::change_back()
{
    header.ar_hrd = ntohs(header.ar_hrd);
    header.ar_pro = ntohs(header.ar_pro);
    header.ar_op = ntohs(header.ar_op);
}