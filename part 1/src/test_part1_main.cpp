#ifndef DEVICE_H
#define DEVICE_H

#include <pcap/pcap.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <cstring>
#include "device.h"
#endif

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t ** alldevs;
    if (pcap_findalldevs(alldevs, errBuf) < 0) {
        dbg_printf("[Error] [findalldevs]");
        return 0;
    }
    pcap_if_t * head = *alldevs;
    while (head->next != NULL) {
        printf("[Name: %s] [Description : %s]\n", head->name, head->description);
        head = head->next;
    }
    DeviceManager manager;
    manager.setFrameReceiveCallback(myOnReceived);
    return 0;
}