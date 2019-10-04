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
#include <thread>
#include "device.h"
#endif
typedef int (*frameReceiveCallback)(const void*, int);

int get_mac(char * mac, int len_limit, const std::string & name)  
{
    struct ifreq ifreq;
    int sock;

    if ((sock = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }
    strcpy (ifreq.ifr_name, name.c_str()); 
    if (ioctl (sock, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl");
        return -1;
    }
    
    return snprintf (mac, len_limit, "%X:%X:%X:%X:%X:%X", (unsigned char) ifreq.ifr_hwaddr.sa_data[0], 
                    (unsigned char) ifreq.ifr_hwaddr.sa_data[1], (unsigned char) ifreq.ifr_hwaddr.sa_data[2], 
                    (unsigned char) ifreq.ifr_hwaddr.sa_data[3], (unsigned char) ifreq.ifr_hwaddr.sa_data[4], 
                    (unsigned char) ifreq.ifr_hwaddr.sa_data[5]);
}

Device::Device(dev_ID id_, const std::string & name_, const std::string & mac_) 
        : name(name_), id(id_), mac(mac_) {
    memset(errbuf, 0, sizeof(errbuf));
    pcap_t * tmp_pcap = pcap_open_live(name.c_str(), 65536, 0, 0, errbuf);
    if (!pcap) {
        throw "pcap_open_live failed!";
    }
    this->pcap = tmp_pcap;
    t = std::thread(pcap_loop, pcap, -1, my_pcap_callback, (u_char *)NULL);
}

Device::~Device() {
    t.join();
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
}

DeviceManager::~DeviceManager() {
    for (auto & dev : device_list) {
        delete dev;
    }
}

frameReceiveCallback Device::onReceived = myOnReceived;

dev_ID DeviceManager::addDevice(const std::string & dev_name) {
    try {
        for (auto & dev : device_list) {
            if (dev->name == dev_name) {
                return dev->id;
            }
        }
        char mac_[30];
        if (get_mac(mac_, 30, dev_name) < 0) {
            dbg_printf("[Error] [addDevice] GetMac failed! \n");
            return -1;
        }
        dbg_printf("[Info] Mac of device %s is %s \n", dev_name.c_str(), mac_);
        const std::string mac(mac_);
        Device * new_dev = new Device(device_list.size(), dev_name, mac);
        device_list.push_back(new_dev);
        return new_dev->id;
    } catch(const char * err_msg){
        dbg_printf("[Error] [addDevice] %s\n", err_msg);
        return -1;
    }
    return 0;
}

dev_ID DeviceManager::findDevice(const std::string & dev_name) {
    for (auto & dev : device_list) {
        if (dev->name == dev_name) {
            return dev->id; 
        }
    }
    dbg_printf("[Error] [findDevice] No such device in device_list! \n");
    return -1;
}

void my_pcap_callback(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content) {
    dbg_printf("[Info] [Time: %d %d] [Caplen: %d] [Len: %d]\n", 
                (int)packet_header->ts.tv_sec, (int)packet_header->ts.tv_usec,
                packet_header->caplen, packet_header->len);
    if (packet_header->caplen != packet_header->len) {
        dbg_printf("[Error] [my_pcap_callback] Some data is lost!\n");
        return;
    }
    size_t size = packet_header->caplen - 16;
    u_char * content = new u_char(size);
    memcpy(content, packet_content + 12, size);
    // Device::onReceived(content, size);
}