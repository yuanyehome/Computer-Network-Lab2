#ifndef DEBUG_H
#define DEBUG_H
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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <set>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define MAX_ARP_WATING_TIME 2
#define MAX_ARP_RETRY 3
#define MY_ROUTE_PROTO 0xffff
#define ROUTE_OFFLINE_TIME 5
#define ROUTE_INTERVAL 2
#define EMPTY 0
#define OCCUPIED 1
#define retrans_num 5

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
typedef int fd_t;
using namespace std::chrono_literals;
const int MY_FD_MIN = 798515;
const int MY_FD_MAX = INT_MAX;
#endif