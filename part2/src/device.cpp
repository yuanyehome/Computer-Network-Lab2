#include "device.h"

typedef int (*frameReceiveCallback)(const void *, int);

int get_mac(char *mac, int len_limit, const std::string &name) {
#ifdef __APPLE__
  ifaddrs *iflist;
  int found = -1;
  if (getifaddrs(&iflist) == 0) {
    for (ifaddrs *cur = iflist; cur; cur = cur->ifa_next) {
      if ((cur->ifa_addr->sa_family == AF_LINK) &&
          (strcmp(cur->ifa_name, name.c_str()) == 0) && cur->ifa_addr) {
        auto sdl = reinterpret_cast<sockaddr_dl *>(cur->ifa_addr);
        memcpy(mac, LLADDR(sdl), sdl->sdl_alen);
        found = 1;
        break;
      }
    }
    freeifaddrs(iflist);
  }
  return found;
#else
  struct ifreq ifreq;
  int sock;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return -1;
  }
  strcpy(ifreq.ifr_name, name.c_str());
  if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) {
    perror("ioctl");
    return -1;
  }

  return snprintf(mac, len_limit, "%X:%X:%X:%X:%X:%X",
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[0],
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[1],
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[2],
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[3],
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[4],
                  (unsigned char)ifreq.ifr_hwaddr.sa_data[5]);
#endif
}

Device::Device(dev_ID id_, const std::string &name_, const std::string &mac_)
    : name(name_), id(id_), mac(mac_) {
  ifaddrs *if_link;
  if (getifaddrs(&if_link) < 0) {
    throw "[ERROR]getifaddr failed!";
    return;
  }
  dev_ip.s_addr = 0;
  subnetMask.s_addr = 0;
  ifaddrs *tmp;
  while (tmp) {
    if (strcmp(tmp->ifa_name, name_.c_str()) == 0) {
      auto tmp_tmp = (sockaddr_in *)tmp->ifa_addr;
      dev_ip = tmp_tmp->sin_addr;
      tmp_tmp = (sockaddr_in *)tmp->ifa_netmask;
      subnetMask = tmp_tmp->sin_addr;
      dbg_printf("[INFO] The IP address of %s is %s, subnetMask is %s\n",
                 name_.c_str(), inet_ntoa(dev_ip), inet_ntoa(subnetMask));
      break;
    }
    tmp = tmp->ifa_next;
  }
  freeifaddrs(if_link);
  memset(errbuf, 0, sizeof(errbuf));
  pcap_t *tmp_pcap = pcap_open_live(name.c_str(), 65536, 0, 0, errbuf);
  if (!tmp_pcap) {
    throw "pcap_open_live failed!";
    return;
  }
  this->pcap = tmp_pcap;
  args = new callback_args(id_);
  t = std::thread(pcap_loop, pcap, -1, my_pcap_callback, (u_char *)args);
}

Device::~Device() {
  t.join();
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
}

frameReceiveCallback Device::onReceived = myOnReceived;

void my_pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header,
                      const u_char *packet_content) {
  dev_ID id = ((callback_args *)argument)->id;
  dbg_printf("[Info] [dev_ID %d] [Time: %d %d] [Caplen: %d] [Len: %d]\n", id,
             (int)packet_header->ts.tv_sec, (int)packet_header->ts.tv_usec,
             packet_header->caplen, packet_header->len);
  if (packet_header->caplen != packet_header->len) {
    dbg_printf("[Error] [my_pcap_callback] Some data is lost!\n");
    return;
  }
  size_t size = packet_header->caplen - 18;
  u_char *content = new u_char[size];
  ether_header *header = new ether_header();
  memcpy(header, packet_content, 14);
  header->ether_type = ntohs(header->ether_type);
  dbg_printf(
      "[Dest: %2x %2x %2x %2x %2x %2x]\n[Src: %2x %2x %2x %2x %2x "
      "%2x]\n[Ethtype %04x]\n",
      header->ether_dhost[0], header->ether_dhost[1], header->ether_dhost[2],
      header->ether_dhost[3], header->ether_dhost[4], header->ether_dhost[5],
      header->ether_shost[0], header->ether_shost[1], header->ether_shost[2],
      header->ether_shost[3], header->ether_shost[4], header->ether_shost[5],
      header->ether_type);
  memcpy(content, packet_content + 14, size);
  Device::onReceived(content, size);
}