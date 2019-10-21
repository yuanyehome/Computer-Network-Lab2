#include <arpa/inet.h>
#include <assert.h>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <map>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <set>
#include <string>
#include <sys/ioctl.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define DEBUG
#ifdef DEBUG
#define dbg_printf printf

#else
#define dbg_printf(...)
#endif
typedef in_addr ip_addr;
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);
typedef int dev_ID;
typedef int (*frameReceiveCallback)(const void*, int);
typedef int distance;