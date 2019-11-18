#include "DFA.h"
#include "fd.h"
namespace DFA {
std::map<fd_t, dfa_status> status_list;
}
namespace BIND {
std::map<fd_t, sock_msg> bind_list;
}
namespace LISTEN_LIST {
std::mutex change_mutex;
std::vector<listen_mgr> listen_list_mgr;
}

in_port_t get_port(IP::packet& pckt)
{
    return ((tcphdr*)pckt.payload)->th_sport;
}

bool check_SYN(IP::packet& pckt, int len)
{
    return ((tcphdr*)pckt.payload)->syn && (!(((tcphdr*)pckt.payload)->ack));
}

bool check_SYN_ACK(IP::packet& pckt, int len)
{
    return ((tcphdr*)pckt.payload)->syn && ((tcphdr*)pckt.payload)->ack;
}

void handle_SYN_RECV(TCB& task, sockaddr_in* mgr)
{
    tcphdr hdr;
    hdr.syn = 1;
    hdr.ack = 1;
    hdr.th_seq = BIND::bind_list.find(task.conn_fd)->second.my_seq_init;
    hdr.th_ack = task.hdr.th_seq + 1;
    hdr.th_sport = mgr->sin_port;
    hdr.th_dport = task.another_port;
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.check = 0;
    hdr.check = getChecksum(&hdr, 20);
    sendIPPacket(manager, mgr->sin_addr, task.another_ip, IPPROTO_TCP, &hdr, sizeof(hdr));
}
void handle_SYN_ACK_recv(fd_t sock_fd, IP::packet& pckt)
{
    // change status
    if (DFA::status_list.find(sock_fd)->second == DFA::SYN_SENT)
        DFA::change_status(sock_fd, DFA::ESTAB);
    else {
        dbg_printf("\033[32m[handle SYN_ACK recv INFO]\033[0m My status is not SYN_SENT and recv a SYN/ACK, it will be ignored!\n");
        return;
    }
    // send ACK
    tcphdr hdr;
    hdr.ack = 1;
    hdr.th_seq = BIND::bind_list.find(sock_fd)->second.my_seq_init;
    hdr.th_ack = ((tcphdr*)pckt.payload)->th_seq + 1;
    hdr.th_dport = ((tcphdr*)pckt.payload)->th_sport;
    hdr.th_sport = ((tcphdr*)pckt.payload)->th_dport;
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.check = 0;
    hdr.check = getChecksum(&hdr, 20);
    sendIPPacket(manager, pckt.header.ip_dst, pckt.header.ip_src, IPPROTO_TCP, &hdr, sizeof(hdr));
    // change sock_msg, full another_sock
    BIND::bind_list.find(sock_fd)->second.another_addr.sin_addr.s_addr = pckt.header.ip_src.s_addr;
    BIND::bind_list.find(sock_fd)->second.another_addr.sin_port = ((tcphdr*)pckt.payload)->th_sport;
}

void sendSYN(int fd, sockaddr_in end_point, const sockaddr* dst_addr)
{
    tcphdr hdr;
    hdr.syn = 1;
    hdr.th_seq = BIND::bind_list.find(fd)->second.my_seq_init;
    hdr.th_sport = end_point.sin_port;
    hdr.th_dport = ((sockaddr_in*)dst_addr)->sin_port;
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.check = 0;
    hdr.check = getChecksum(&hdr, 20);
    sendIPPacket(manager, end_point.sin_addr, ((sockaddr_in*)dst_addr)->sin_addr, IPPROTO_TCP, &hdr, sizeof(hdr));
}

void change_tcphdr_to_host(tcphdr& hdr)
{
    hdr.th_dport = ntohs(hdr.th_dport);
    hdr.th_sport = ntohs(hdr.th_sport);
    hdr.th_seq = ntohl(hdr.th_seq);
    hdr.th_ack = ntohl(hdr.th_ack);
    hdr.th_win = ntohl(hdr.th_win);
}

void change_tcphdr_to_net(tcphdr& hdr)
{
    hdr.th_dport = htons(hdr.th_dport);
    hdr.th_sport = htons(hdr.th_sport);
    hdr.th_seq = htonl(hdr.th_seq);
    hdr.th_ack = htonl(hdr.th_ack);
    hdr.th_win = htonl(hdr.th_win);
}

int DFA::change_status(fd_t fd, dfa_status status)
{
    status_mutex.lock();
    if (status_list.find(fd) == status_list.end()) {
        dbg_printf("033[31m[CHANGE STATUS ERROR] No such fd!\n");
        status_mutex.unlock();
        return -1;
    }
    status_list[fd] = status;
    status_mutex.unlock();
    return 0;
}

int TCP_handler(IP::packet& pckt, int len)
{
    tcphdr hdr = *(tcphdr*)(pckt.payload);
    change_tcphdr_to_host(hdr);
    if (check_SYN(pckt, len)) {
        LISTEN_LIST::change_mutex.lock();
        for (auto& item : LISTEN_LIST::listen_list_mgr) {
            if (item.sock->sin_addr.s_addr == pckt.header.ip_dst.s_addr && (item.sock->sin_port == hdr.th_dport)) {
                in_port_t another_port = get_port(pckt);
                item.listen_list.push_back(TCB(-1, pckt.header.ip_src, another_port, hdr));
                LISTEN_LIST::change_mutex.unlock();
                return 0;
            }
        }
        LISTEN_LIST::change_mutex.unlock();
        dbg_printf("\033[32m[INFO] [TCP_handler] [SYN]\033[0m This IP is not listening, \
            and this packet will be dropped! \n");
        return -1;
    } else if (check_SYN_ACK(pckt, len)) {
        ip_addr sock_ip = pckt.header.ip_dst;
        in_port_t sock_port = ((tcphdr*)pckt.payload)->th_dport;
        Device* dev_ptr = manager.findDevice(sock_ip);
        if (dev_ptr == NULL) {
            dbg_printf("\033[31m[TCP_handler ERROR]\033[0m Something is wrong, I don't have this IP!\n");
            return -1;
        }
        dev_ptr->port_mutex.lock();
        if (!dev_ptr->empty_port[sock_port]) {
            dev_ptr->port_mutex.unlock();
            dbg_printf("\033[31m[TCP_handler ERROR]\033[0m Something is wrong, I don't have this port!\n");
            return -1;
        }
        dev_ptr->port_mutex.unlock();
        sockaddr_in sock;
        sock.sin_addr = sock_ip;
        sock.sin_port = sock_port;
        fd_t sock_fd = BIND::findFdBySock(sock);
        handle_SYN_ACK_recv(sock_fd, pckt);
    } else {
        // not implemented
    }
    return 0;
}

fd_t __wrap_socket(int domain, int type, int protocol)
{
    if (domain == PF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP) {
        for (int i = FD::MY_FD_MAX; i >= FD::MY_FD_MIN; --i) {
            if (FD::allovated_fds.find(i) == FD::allovated_fds.end()) {
                DFA::status_mutex.lock();
                DFA::status_list[i] = DFA::CLOSED;
                DFA::status_mutex.unlock();
                FD::allovated_fds.insert(i);
                assert(BIND::bind_list.find(i) == BIND::bind_list.end());
                return i;
            } else {
                continue;
            }
        }
        dbg_printf("\033[31m[ALLOCATING FD ERROR]\033[0m No free fd!\n");
        return -1;
    } else {
        dbg_printf("\033[31m[UNSUPPORTED ARGUMENTS]\033[0m This function is unimplemented!\n");
        return -1;
    }
}

int __wrap_bind(fd_t socket, const struct sockaddr* address,
    socklen_t address_len)
{
    assert(BIND::bind_list.find(socket) == BIND::bind_list.end());
    ip_addr sock_ip;
    in_port_t sock_port;
    sock_ip.s_addr = ((sockaddr_in*)address)->sin_addr.s_addr;
    sock_port = ((sockaddr_in*)address)->sin_port;
    if (sock_ip.s_addr == INADDR_ANY) {
        // not implemented
    } else {
        auto dev_ptr = manager.findDevice(sock_ip);
        if (dev_ptr == NULL) {
            dbg_printf("\033[31m[BIND ERROR] Illegal IP address!\n");
            return -1;
        }
        dev_ptr->port_mutex.lock();
        if (dev_ptr->empty_port[sock_port]) {
            dbg_printf("\033[31m[BIND ERROR] This is an occupied port!\n");
            dev_ptr->port_mutex.unlock();
            return -1;
        }
        if (sock_port == 0) {
            for (int _ = 1024; _ <= 65536; ++_) {
                if (!dev_ptr->empty_port[_]) {
                    sock_port = _;
                    break;
                }
            }
        }
        dev_ptr->empty_port[sock_port] = 1;
        dev_ptr->port_mutex.unlock();
    }
    try {
        BIND::bind_list[socket] = sock_msg();
        BIND::bind_list[socket].addr.sin_addr.s_addr = sock_ip.s_addr;
        BIND::bind_list[socket].addr.sin_port = sock_port;
        return 0;
    } catch (const char* e) {
        dbg_printf("\033[31m[BIND ERROR]\033[0m e\n");
        return -1;
    }
}

int __wrap_listen(int socket, int backlog)
{
    try {
        if (BIND::bind_list.find(socket) == BIND::bind_list.end()) {
            dbg_printf("\033[31m[LISTEN ERROR]\033[0m This fd is not allocated\n");
            return -1;
        }
        sockaddr_in& this_sock = BIND::bind_list[socket].addr;
        if (this_sock.sin_addr.s_addr == 0 || this_sock.sin_port == 0) {
            dbg_printf("\033[31m[LISTEN ERROR]\033[0m Please specify IP address and port for listening by using function bind()\n");
            return -1;
        }
        LISTEN_LIST::change_mutex.lock();
        DFA::status_mutex.lock();
        LISTEN_LIST::listen_list_mgr.push_back(listen_mgr(socket, &this_sock));
        DFA::status_list[socket] = DFA::LISTEN;
        DFA::status_mutex.unlock();
        LISTEN_LIST::change_mutex.unlock();
        // tell TCP_handler it can push item into listen_list;
        dbg_printf("\033[32m[INFO] [START LISTENING]\033[0m\n");
    } catch (const char* e) {
        dbg_printf("\033[31m[LISTEN ERROR]\033[0m e\n");
        return -1;
    }
    return 0;
}

int __wrap_accept(int socket, struct sockaddr* address,
    socklen_t* address_len)
{
    if (address == NULL) {
        if (address_len != NULL) {
            dbg_printf("\033[31m[ACCEPT ERROR]\033[0m \
                Please set address_len as 0 if you don't want client sockaddr\n");
            return -1;
        }
    }
    bool is_find = false;
    for (auto& item : LISTEN_LIST::listen_list_mgr) {
        if (socket == item.mgr_fd) {
            is_find = true;
            while (1) {
                LISTEN_LIST::change_mutex.lock();
                if (item.listen_list.size() == 0) {
                    LISTEN_LIST::change_mutex.unlock();
                    continue;
                } else {
                    TCB task = item.listen_list[0];
                    task.conn_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
                    BIND::bind_list[task.conn_fd] = sock_msg();
                    BIND::bind_list[task.conn_fd].addr.sin_family = AF_INET;
                    BIND::bind_list[task.conn_fd].addr.sin_addr.s_addr = task.another_ip.s_addr;
                    BIND::bind_list[task.conn_fd].addr.sin_port = task.another_port;
                    BIND::bind_list.find(task.conn_fd)->second.another_seq_init = task.hdr.th_seq;
                    change_status(task.conn_fd, DFA::SYN_RCVD);
                    handle_SYN_RECV(task, item.sock);
                    item.listen_list.erase(item.listen_list.begin());
                    LISTEN_LIST::change_mutex.unlock();
                    if (address != NULL) {
                        memcpy(address, &BIND::bind_list[task.conn_fd].addr, sizeof(sockaddr_in));
                        *address_len = sizeof(sockaddr_in);
                    }
                    return 0;
                }
            }
        }
    }
    if (!is_find) {
        dbg_printf("\033[31m[ACCEPT ERROR]\033[0m You are trying to accept a fd which is not listening! \n");
        return -1;
    }
    return 0;
}

int __wrap_connect(int socket, const struct sockaddr* address,
    socklen_t address_len)
{
    //check socket
    if (BIND::bind_list.find(socket) == BIND::bind_list.end()) {
        dbg_printf("\033[31m[CONNECT ERROR]\033[0m This fd is not allocated\n");
        return -1;
    }
    // check if sockaddr.ip and sockaddr.port are zero.
    ip_addr serverIP = ((sockaddr_in*)address)->sin_addr;
    in_port_t serverPort = ((sockaddr_in*)address)->sin_port;
    sockaddr_in end_point = BIND::bind_list.find(socket)->second.addr;
    if (end_point.sin_addr.s_addr == 0) {
        for (auto& item : Router::router_mgr.routetable) {
            if (item.contain_ip(serverIP)) {
                end_point.sin_addr.s_addr = item.dev_ptr->dev_ip.s_addr;
                break;
            }
        }
        if (end_point.sin_addr.s_addr == 0) {
            dbg_printf("\033[31m[CONNECT ERROR]\033[0m Cann't find via device in route table!\n");
            return -1;
        }
    }
    if (end_point.sin_port == 0) {
        // assign a port if no port provided
        auto dev_ptr = manager.findDevice(end_point.sin_addr);
        if (dev_ptr == NULL) {
            dbg_printf("\033[31m[CONNECT ERROR] Illegal IP address!\n");
            return -1;
        }
        dev_ptr->port_mutex.lock();
        for (int _ = 1024; _ <= 65536; ++_) {
            if (!dev_ptr->empty_port[_]) {
                end_point.sin_port = _;
                break;
            }
        }
        dev_ptr->empty_port[end_point.sin_port] = 1;
        dev_ptr->port_mutex.unlock();
    }
    sendSYN(socket, end_point, address);
    DFA::change_status(socket, DFA::SYN_SENT);
    return 0;
}

int __wrap_getaddrinfo(const char* node, const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res)
{
    if (hints->ai_family == AF_INET && hints->ai_protocol == IPPROTO_TCP && hints->ai_socktype == SOCK_STREAM) {
        addrinfo* head = new addrinfo;
        *res = head;
        head->ai_next = NULL;
        sockaddr_in* tmp = new sockaddr_in;
        inet_pton(AF_INET, node, &tmp->sin_addr.s_addr);
        tmp->sin_addr.s_addr = htonl(tmp->sin_addr.s_addr);
        tmp->sin_port = htons(atoi(service));
        head->ai_addr = (sockaddr*)(tmp);
        head->ai_addrlen = sizeof(sockaddr_in);
        return 0;
    } else {
        dbg_printf("\033[31m[GETADDRINFO ERROR] [UNSUPPORTED FLAGS]\033[0m\n");
        return -1;
    }
}

int __wrap__freeaddrinfo(addrinfo* ai)
{
    addrinfo* next;
    while (ai != NULL) {
        next = ai->ai_next;
        delete ai;
        ai = next;
    }
    return 0;
}