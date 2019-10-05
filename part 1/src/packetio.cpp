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
typedef int (*frameReceiveCallback)(const void *, int);

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
int Device::sendFrame(const void *buf, int len, int ethtype, const void *destmac)
{
    size_t size = len + 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN + ETHER_CRC_LEN;
    u_char *frame = new u_char[size];
    ether_header *header = new ether_header();
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        header->ether_dhost[i] = *((u_int8_t *)(destmac) + i);
        header->ether_shost[i] = (u_int8_t)this->mac[i];
    }
    header->ether_type = htons(ethtype);

    dbg_printf("%ld\n", sizeof(*header));
    assert(sizeof(*header) == 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN);

    memcpy(frame, header, 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN);
    memcpy(frame + 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN, buf, len);
    for (int i = size - ETHER_TYPE_LEN; i < size; ++i)
    {
        frame[i] = 0;
        // checksum, not implement;
    }
    int stat = pcap_sendpacket(pcap, (u_char *)frame, size);
    delete frame;
    if (stat < 0)
    {
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

int myOnReceived(const void *buf, int len)
{
    dbg_printf("[Info] [Payload]: ");
    for (int i = 0; i < len; ++i)
    {
        dbg_printf("%02x ", *(u_int8_t *)((u_char *)buf + i));
    }
    dbg_printf("\n");
    return 0;
}

int DeviceManager::setFrameReceiveCallback(frameReceiveCallback callback)
{
    try
    {
        Device::onReceived = callback;
    }
    catch (const char *err_msg)
    {
        dbg_printf("[Error] [setFrameReceiveCallback] %s\n", err_msg);
        return -1;
    }
    return 0;
}
