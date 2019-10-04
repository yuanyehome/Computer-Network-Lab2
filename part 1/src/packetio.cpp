#ifndef DEVICE_H
#define DEVICE_H

#include <pcap/pcap.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <netinet/ether.h>
#include "device.h"
#endif
typedef int (*frameReceiveCallback)(const void*, int);


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
int Device::sendFrame(const void* buf, int len, int ethtype, const void* destmac) {
    size_t size = len + 2 * ETHER_ADDR_LEN + 4;
    u_char * frame = new u_char(size);
    memcpy(frame, destmac, ETHER_ADDR_LEN);
    memcpy(frame + ETHER_ADDR_LEN, mac.c_str(), ETHER_ADDR_LEN);
    memcpy(frame + 2 * ETHER_ADDR_LEN, buf, len);
    for (int i = size - 4; i < size; ++i) {
        frame[i] = 0;
        // checksum, not implement;
    }
    int stat = pcap_sendpacket(pcap, (u_char *)frame, size);
    delete frame;
    if (stat < 0) {
        dbg_printf("[Error] [sendFrame] [pcap_sendpacket]");
        return -1;
    }
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

int myOnReceived(const void * buf, int len) {
    dbg_printf("[Info] [Payload]: ");
    for (int i = 0; i < len; ++i) {
        dbg_printf("%02x ", *(u_int8_t *)((u_char *)buf + i));
    }
    dbg_printf("\n");
    return 0;
}

int DeviceManager::setFrameReceiveCallback(frameReceiveCallback callback) {
        try {
            Device::onReceived = callback;
        } catch(const char * err_msg) {
            dbg_printf("[Error] [setFrameReceiveCallback] %s\n", err_msg);
            return -1;
        }
        return 0;
    }
