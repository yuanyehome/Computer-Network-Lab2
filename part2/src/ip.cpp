#include "ip.h"
#include "arp.h"
#include "device.h"

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
    dstMAC = arp::findMAC(dev_ptr, dest);
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