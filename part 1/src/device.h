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
#include <assert.h>
#include "DEBUG.h"


typedef int dev_ID;
typedef int (*frameReceiveCallback)(const void*, int);
void my_pcap_callback(u_char* argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content);
int myOnReceived(const void * buf, int len);

struct Device {
    dev_ID id;
    std::string name;
    const std::string & mac;
    pcap_t * pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::thread t;
    static frameReceiveCallback onReceived;

    Device(dev_ID id_, const std::string & name_, const std::string & mac_);
    ~Device();
    int sendFrame(const void* buf, int len, int ethtype, const void* destmac);
};


struct DeviceManager {
    std::vector<Device *> device_list;

    dev_ID addDevice(const std::string & dev_name);
    dev_ID findDevice(const std::string & dev_name);
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
