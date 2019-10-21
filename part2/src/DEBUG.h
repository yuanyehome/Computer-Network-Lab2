#include <cstdio>
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
#include <netinet/ip.h>

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