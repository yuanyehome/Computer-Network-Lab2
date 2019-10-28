#include "arp.h"

typedef int (*frameReceiveCallback)(const void*, int);

std::string MacToString(const u_char* mac)
{
    char tmp[30];
    snprintf(tmp, 30, "%X:%X:%X:%X:%X:%X",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);
    return std::string(tmp);
}

int get_mac(char* mac, int len_limit, const std::string& name)
{
#ifdef __APPLE__
    ifaddrs* iflist;
    u_char tmp[6] = { 0 };
    int found = -1;
    if (getifaddrs(&iflist) == 0) {
        for (ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {
            if ((cur->ifa_addr->sa_family == AF_LINK) && (strcmp(cur->ifa_name, name.c_str()) == 0) && cur->ifa_addr) {
                auto sdl = reinterpret_cast<sockaddr_dl*>(cur->ifa_addr);
                memcpy(tmp, LLADDR(sdl), sdl->sdl_alen);
                found = 1;
                break;
            }
        }
        freeifaddrs(iflist);
    }
    if (found > 0) {
        snprintf(mac, len_limit, "%X:%X:%X:%X:%X:%X",
            tmp[0], tmp[1], tmp[2],
            tmp[3], tmp[4], tmp[5]);
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

Device::Device(dev_ID id_, const std::string& name_, const std::string& mac_)
    : name(name_)
    , id(id_)
    , mac(mac_)
{
    ifaddrs* if_link;
    if (getifaddrs(&if_link) < 0) {
        throw "\033[31m[ERROR]\033[0mgetifaddr failed!";
        return;
    }
    dev_ip.s_addr = 0;
    subnetMask.s_addr = 0;
    ifaddrs* tmp = if_link;
    while (tmp) {
        if (strcmp(tmp->ifa_name, name_.c_str()) == 0 && tmp->ifa_addr->sa_family == AF_INET) {
            // std::cout << "here debug: [NAME] " << tmp->ifa_name << std::endl;
            // std::cout << "here debug: [AF_INET] " << (int)tmp->ifa_addr->sa_family << std::endl;
            auto tmp_tmp = (sockaddr_in*)(tmp->ifa_addr);
            dev_ip = tmp_tmp->sin_addr;
            tmp_tmp = (sockaddr_in*)(tmp->ifa_netmask);
            subnetMask = tmp_tmp->sin_addr;
            char tmp_ip[30], tmp_mask[30];
            strcpy(tmp_ip, inet_ntoa(dev_ip));
            strcpy(tmp_mask, inet_ntoa(subnetMask));
            dbg_printf("\033[32m[INFO]\033[0m The IP address of %s is %s, subnetMask is %s\n",
                name_.c_str(), IPtoStr(dev_ip).c_str(), IPtoStr(subnetMask).c_str());
            dbg_printf("\033[35m[Compare INFO]\033[0m The IP address of %s is %s, subnetMask is %s\n",
                name_.c_str(), tmp_ip, tmp_mask);
            break;
        }
        tmp = tmp->ifa_next;
    }
    if (dev_ip.s_addr == 0)
        dbg_printf("\033[31m[WARNING]\033[0m This device have no IP\n");
    freeifaddrs(if_link);
    memset(errbuf, 0, sizeof(errbuf));
    pcap_t* tmp_pcap = pcap_open_live(name.c_str(), 65536, 0, 0, errbuf);
    if (!tmp_pcap) {
        throw "pcap_open_live failed!";
        return;
    }
    this->pcap = tmp_pcap;
    args = new callback_args(id_, this);
    t = std::thread(pcap_loop, pcap, -1, my_pcap_callback, (u_char*)args);
}

Device::~Device()
{
    t.join();
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
}

frameReceiveCallback Device::onReceived = myOnReceived;

std::pair<std::string, std::string> genMAC(const ether_header* header)
{
    char tmp1[20], tmp2[20] = { 0 };
    snprintf(tmp1, 20, "%X:%X:%X:%X:%X:%X",
        (unsigned char)header->ether_dhost[0],
        (unsigned char)header->ether_dhost[1],
        (unsigned char)header->ether_dhost[2],
        (unsigned char)header->ether_dhost[3],
        (unsigned char)header->ether_dhost[4],
        (unsigned char)header->ether_dhost[5]);
    snprintf(tmp2, 20, "%X:%X:%X:%X:%X:%X",
        (unsigned char)header->ether_shost[0],
        (unsigned char)header->ether_shost[1],
        (unsigned char)header->ether_shost[2],
        (unsigned char)header->ether_shost[3],
        (unsigned char)header->ether_shost[4],
        (unsigned char)header->ether_shost[5]);
    return std::make_pair<std::string, std::string>(std::string(tmp1), std::string(tmp2));
}

void my_pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header,
    const u_char* packet_content)
{
    dev_ID id = ((callback_args*)argument)->id;
    Device* dev_ptr = ((callback_args*)argument)->dev_ptr;
    dbg_printf("\033[32m[INFO]\033[0m [dev_ID %d] [Time: %d %d] [Caplen: %d] [Len: %d]\n", id,
        (int)packet_header->ts.tv_sec, (int)packet_header->ts.tv_usec,
        packet_header->caplen, packet_header->len);
    if (packet_header->caplen != packet_header->len) {
        dbg_printf("\033[31m[ERROR]\033[0m [my_pcap_callback] Some data is lost!\n");
        return;
    }
    size_t size = packet_header->caplen - 18;
    u_char* content = new u_char[size];
    ether_header* header = new ether_header();
    memcpy(header, packet_content, 14);
    header->ether_type = ntohs(header->ether_type);
    dbg_printf(
        "[Dest: %X:%X:%X:%X:%X:%X]\n[Src: %X:%X:%X:%X:%X:%X]\n[Ethtype %04x]\n",
        header->ether_dhost[0], header->ether_dhost[1], header->ether_dhost[2],
        header->ether_dhost[3], header->ether_dhost[4], header->ether_dhost[5],
        header->ether_shost[0], header->ether_shost[1], header->ether_shost[2],
        header->ether_shost[3], header->ether_shost[4], header->ether_shost[5],
        header->ether_type);
    if (header->ether_type == ETHERTYPE_ARP) {
        dbg_printf("\033[33m[Special INFO][This is an ARP frame]\033[0m\n");
    }
    std::string dstMAC, srcMAC;
    std::pair<std::string, std::string> res = genMAC(header);
    dstMAC = res.first;
    srcMAC = res.second;
    if ((srcMAC == dev_ptr->mac) || ((dstMAC != dev_ptr->mac) && dstMAC != "FF:FF:FF:FF:FF:FF"))
        return;
    if (header->ether_type == ETHERTYPE_ARP) {
        // ARP Related
        arp::arpPacket pckt(packet_content + 14);
        dbg_printf("\033[33m[INFO]\033[0m [ARP_OP: %d]", pckt.header.ar_op);
        if (pckt.header.ar_op == ARPOP_REQUEST) {
            arp::handleARPRequest(dev_ptr, pckt);
        } else if (pckt.header.ar_op == ARPOP_REPLY) {
            arp::handleARPReply(packet_content + 14, size, srcMAC);
        } else {
            dbg_printf("\033[31m[WARNING]\033[0m [Unsupported arp op type]");
            return;
        }
    }
    memcpy(content, packet_content + 14, size);
    Device::onReceived(content, size);
}