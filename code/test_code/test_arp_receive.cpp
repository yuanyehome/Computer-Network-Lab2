#include "arp.h"

int main()
{
    std::cout << "ARP hdr size " << sizeof(arphdr) << std::endl;
    std::cout << "ARP packet size " << sizeof(arp::arpPacket) << std::endl;
    char errBuf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errBuf) < 0) {
        dbg_printf("\033[31m[ERROR]\033[0m [findalldevs]");
        return 0;
    }
    pcap_if_t* head = alldevs;
    DeviceManager manager;
    manager.setFrameReceiveCallback(myOnReceived);
    IP::setIPPacketReceiveCallback(IP::myIPCallback);
    while (head->next != NULL) {
        dbg_printf("\033[32m[INFO]\033[0m [Name: %s] [Description : %s]\n", head->name, head->description);
        if (manager.addDevice(std::string(head->name)) < 0) {
            dbg_printf("\033[32m[INFO]\033[0m [Name: %s] add failed!\n", head->name);
        } else {
            dbg_printf("\033[32m[INFO]\033[0m [Name: %s] add succeeded!\n", head->name);
        }
        dbg_printf("\n");
        head = head->next;
    }

    return 0;
}