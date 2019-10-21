#include <arpa/inet.h>
#include <assert.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>

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