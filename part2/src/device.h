#ifndef DEVICE_H_
#define DEVICE_H_

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
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <net/if_dl.h>
#include "DEBUG.h"

typedef int dev_ID;
typedef int (*frameReceiveCallback)(const void *, int);
void my_pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
int myOnReceived(const void *buf, int len);
void strToMac(std::string &mac, void *buf);

/*
Description of this file:
1) struct Device: send and manage a thread of pcap_loop;
2) struct DeviceManager: manage all the devices;
*/

struct callback_args
{
    dev_ID id;
    callback_args(dev_ID id_) : id(id_) {}
};

struct Device
{
    dev_ID id;
    std::string name;
    const std::string mac;
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::thread t;
    static frameReceiveCallback onReceived;
    callback_args *args;

    Device(dev_ID id_, const std::string &name_, const std::string &mac_);
    ~Device();
    /*
     * @send a frame to destmac
     * @param buf buffer of payload
     * @param len length of payload
     * @param ethtype type of eth, don't forget the byte order
     * @param destmac destination
    */
    int sendFrame(const void *buf, int len, int ethtype, const void *destmac);
};

struct DeviceManager
{
    std::vector<Device *> device_list;

    dev_ID addDevice(const std::string &dev_name);
    dev_ID findDevice(const std::string &dev_name);
    /**
     * @brief Register a callback function to be called each time an Ethernet II 
     * frame was received.
     *
     * @param callback the callback function.
     * @return 0 on success, -1 on error.
     * @see frameReceiveCallback
     */
    int setFrameReceiveCallback(frameReceiveCallback callback);
    ~DeviceManager();
};

#endif