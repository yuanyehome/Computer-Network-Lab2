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
    DeviceManager manager;
    manager.setFrameReceiveCallback(myOnReceived);
    while (head->next != NULL) {
        dbg_printf("[Info] [Name: %s] [Description : %s]\n", head->name, head->description);
        // if (manager.addDevice(std::string(head->name)) < 0) {
        //     dbg_printf("[Info] [Name: %s] add failed!\n", head->name);
        // }
        // else {
        //     dbg_printf("[Info] [Name: %s] add succeeded!\n", head->name);
        // }
        // dbg_printf("\n");
        // break;
        head = head->next;
    }
    if (manager.addDevice(std::string("enp0s31f6")) < 0) {
        dbg_printf("[Info] [Name: %s] add failed!\n", head->name);
    }
    else {
        dbg_printf("[Info] [Name: %s] add succeeded!\n", head->name);
    }

    return 0;
}