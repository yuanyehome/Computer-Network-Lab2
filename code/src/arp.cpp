#include "arp.h"

namespace arp {
std::map<const ip_addr, const std::string, compare_ip> arp_map;
std::mutex condition_mutex;
uint8_t cond;
}
std::string arp::findMAC(Device* dev_ptr, ip_addr target_ip)
{
    if (arp_map.find(target_ip) != arp_map.end()) {
        return arp_map.at(target_ip);
    } else {
        sendARPRequest(dev_ptr, target_ip);
        int time_variable = 0;
        int retry = 0;
        cond = 1;
        while (1) {
            sleep(100);
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
                dbg_printf("[INFO] [arp::findMAC] [sendARPRequest Retrying] [targetIP: %s] [device_name: %s]",
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
                    dbg_printf("[ERROR] [ARP failed] [targetIP: %s] [device_name: %s]",
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
    u_char* char_mac = new u_char[6];
    memset(char_mac, 0xff, 6);
    u_char* buf = new u_char[4];
    memcpy(buf, (u_char*)&target_ip, 4);
    dev_ptr->sendFrame(buf, 4, ETHERTYPE_ARP, char_mac);
    delete[] buf;
    delete[] char_mac;
}

void arp::sendARPReply(Device* dev_ptr, std::string& dstMac, const ip_addr srcIP)
{
    // if not request me
    if (srcIP.s_addr != dev_ptr->dev_ip.s_addr)
        return;
    // else
    u_char IP[4];
    memcpy(IP, (u_char*)&(srcIP), 4);
    dbg_printf("[INFO] [FUNCTION] [sendARPReply] Reply an ARP Request for [IP: %s] from [MAC: %s]\n",
        IPtoStr(srcIP).c_str(), dstMac.c_str());
    dev_ptr->sendFrame(IP, 4, ETHERTYPE_ARP, dstMac.c_str());
    return;
}

void arp::handleARPReply(const void* buf, int len, std::string& targetMAC)
{

    assert(len == 4);
    ip_addr* ip_ptr = (ip_addr*)buf;
    assert(arp_map.find(*ip_ptr) == arp_map.end());
    assert(cond == 1);
    condition_mutex.lock();
    arp_map.insert(std::make_pair(*ip_ptr, targetMAC));
    cond = 0;
    condition_mutex.unlock();
}