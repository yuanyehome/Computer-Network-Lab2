#include "DEBUG.h"
#include "device.h"
#include "ip.h"
#include <assert.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <vector>
typedef int (*frameReceiveCallback)(const void*, int);

void strToMac(const std::string& mac, u_char* buf)
{
    int tmp[6];
    sscanf(mac.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", tmp, tmp + 1, tmp + 2, tmp + 3,
        tmp + 4, tmp + 5);
    for (int i = 0; i < 6; ++i) {
        buf[i] = (u_char)tmp[i];
    }
}
/**
 * @brief Encapsulate some data into an Ethernet II frame and send it.
 *
 * @param buf Pointer to the payload.
 * @param len Length of the payload.
 * @param ethtype EtherType field value of this frame.
 * @param destmac MAC address of the destination.
 * @param id ID of the device(returned by `addDevice`) to send on.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */
int Device::sendFrame(const void* buf, int len, int ethtype,
    const void* destmac) const
{
    if (len > 20) {
        dbg_printf("\033[31m[DEBUG---------------]\033[0m");
        for (int i = 0; i < len - 20; ++i) {
            dbg_printf("%x ", *((u_char*)buf + i + 20));
        }
    }
    dbg_printf("\n[Function: sendFrame]***************\n");
    size_t size = len + 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN + ETHER_CRC_LEN;
    u_char* frame = new u_char[size];
    ether_header* header = new ether_header();
    // dbg_printf("[DEBUG] %s\n", this->mac.c_str());
    u_char* tmp = new u_char[6];
    strToMac(this->mac, tmp);
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        header->ether_dhost[i] = *((u_int8_t*)(destmac) + i);
        header->ether_shost[i] = (u_int8_t)tmp[i];
        // dbg_printf("[DEBUG] [sendFrame] [Mac %0X]\n", tmp[i]);
    }
    header->ether_type = htons(ethtype);
    assert(sizeof(*header) == 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN);

    memcpy(frame, header, 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN);
    if (len) {
        memcpy(frame + 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN, buf, len);
    }
    for (int i = size - ETHER_CRC_LEN; i < size; ++i) {
        frame[i] = 0;
        // checksum, not implement;
    }
    int stat = pcap_sendpacket(pcap, (u_char*)frame, size);
    delete[] tmp;
    delete[] frame;
    if (stat < 0) {
        dbg_printf("\033[31m[ERROR]\033[0m [sendFrame] [pcap_sendpacket]\n");
        return -1;
    }
    dbg_printf("\033[32m[INFO]\033[0m [sendFrame] send succeeded! [size: %d]\n", (int)size);
    return 0;
}

/**
 * @brief Process a frame upon receiving it.
 *
 * @param buf Pointer to the frame.
 * @param len Length of the frame.
 * @param id ID of the device (returned by `addDevice`) receiving current
 * frame.
 * @return 0 on success, -1 on error.
 * @see addDevice
 */

int myOnReceived(const void* buf, int len)
{
    dbg_printf("\n[Function: myOnReceived]***************\n");
    dbg_printf("\033[32m[INFO]\033[0m [Payload]: ");
    int tmp_len = std::min(len, 10);
    for (int i = 0; i < tmp_len; ++i) {
        dbg_printf("%0X ", *(u_int8_t*)((u_char*)buf + i));
    }
    dbg_printf("\n");
    if (len > 10) {
        dbg_printf("......\n");
    }
    IP::IPCallback(buf, len);
    return 0;
}

int DeviceManager::setFrameReceiveCallback(frameReceiveCallback callback)
{
    dbg_printf("\n[Function: setFrameReceiveCallback]***************\n");
    try {
        Device::onReceived = callback;
    } catch (const char* err_msg) {
        dbg_printf("\033[31m[ERROR]\033[0m [setFrameReceiveCallback] %s\n", err_msg);
        return -1;
    }
    return 0;
}
