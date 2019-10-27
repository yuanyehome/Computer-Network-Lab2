#include <arpa/inet.h>
#include <assert.h>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <map>
#include <mutex>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <set>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define MAX_ARP_WATING_TIME 2
#define MAX_ARP_RETRY 3

#define DEBUG
#ifdef DEBUG
#define dbg_printf printf

#else
#define dbg_printf(...)
#endif
typedef in_addr ip_addr;
typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
typedef int dev_ID;
typedef int (*frameReceiveCallback)(const void *, int);
typedef int distance;