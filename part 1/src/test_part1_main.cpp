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
#include <net/ethernet.h>
#include <cstring>
#include <thread>
#include <assert.h>
#include "DEBUG.h"
#endif
#include "device.h"
#include <ctime>
#include <unistd.h>


/*
Description of this file:
1) find all devices and try to add them to device_list;
2) each device will send a packet to "ff:ff:ff:ff:ff:ff" every 5 seconds;
3) During Device initianlizing, it will create a thread using "pcap_loop" to receive packets;
*/

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errBuf) < 0)
    {
        dbg_printf("[Error] [findalldevs]");
        return 0;
    }
    pcap_if_t *head = alldevs;
    DeviceManager manager;
    manager.setFrameReceiveCallback(myOnReceived);
    while (head->next != NULL)
    {
        dbg_printf("[Info] [Name: %s] [Description : %s]\n", head->name, head->description);
        if (manager.addDevice(std::string(head->name)) < 0)
        {
            dbg_printf("[Info] [Name: %s] add failed!\n", head->name);
        }
        else
        {
            dbg_printf("[Info] [Name: %s] add succeeded!\n", head->name);
        }
        dbg_printf("\n");
        head = head->next;
    }

    while (1)
    {
        for (auto & device : manager.device_list) {
            dbg_printf("[name: %s] [id: %d]\n", device->name.c_str(), device->id);
            u_char * content = new u_char[100];
            memset(content, 15, 100);
            u_char * dest_mac = new u_char[6];
            memset(dest_mac, 255, 6);
            device->sendFrame(content, 100, 0x0800, dest_mac);
            delete[] content;
            delete[] dest_mac;
        }
        sleep(5);
    }

    // if (manager.addDevice(std::string("lo")) < 0)
    // {
    //     dbg_printf("[Info] [Name: %s] add failed!\n", "lo");
    // }
    // else
    // {
    //     dbg_printf("[Info] [Name: %s] add succeeded!\n", "lo");
    // }
    // dbg_printf("\n");

    return 0;
}