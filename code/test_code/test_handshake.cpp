#include "DFA.h"
#include "fd.h"

int main()
{
    char errBuf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errBuf) < 0) {
        dbg_printf("\033[31m[ERROR]\033[0m [findalldevs]");
        return 0;
    }
    pcap_if_t* head = alldevs;
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
    Router::router_mgr.initializeTable(manager);
    IP::startBroadcast(manager);

    int test_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    printf("\033[36m[MAIN]\033[0m%d\n", test_fd);
    sockaddr_in addr_in;
    addr_in.sin_addr.s_addr = 10 + (100 << 8) + (1 << 16) + (1 << 24);
    addr_in.sin_port = 10000;
    printf("\033[36m[MAIN]\033[0m%s\n", IPtoStr(addr_in.sin_addr).c_str());
    __wrap_bind(test_fd, (sockaddr*)(&addr_in), sizeof(addr_in));
    __wrap_listen(test_fd, 100);
    __wrap_accept(test_fd, NULL, NULL);
    return 0;
}