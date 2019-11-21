#include "DFA.h"
#include "fd.h"
namespace DFA {
std::mutex status_mutex;
std::map<fd_t, dfa_status> status_list;
}
namespace FD {
std::set<int> allovated_fds;
}

std::condition_variable cv;
std::condition_variable cv_read;
std::condition_variable cv_close;
std::mutex ack_mutex;
std::mutex read_mutex;
std::mutex fin_mutex;
namespace BIND {
std::mutex msg_mutex;
std::map<fd_t, sock_msg> bind_list;
fd_t findFdBySock(sockaddr_in sock, sockaddr_in another_sock)
{
    for (auto& item : bind_list) {
        dbg_printf("%d %s %d\n", item.first, IPtoStr(item.second.addr.sin_addr).c_str(), item.second.addr.sin_port);
        dbg_printf("%s %d\n", IPtoStr(sock.sin_addr).c_str(), sock.sin_port);
        if (((item.second.addr.sin_addr.s_addr == sock.sin_addr.s_addr
                 && item.second.addr.sin_port == sock.sin_port)
                || (item.second.another_addr.sin_addr.s_addr == another_sock.sin_addr.s_addr
                       && item.second.another_addr.sin_port == another_sock.sin_port))
            && !item.second.is_listening)
            return item.first;
    }
    return -1;
}
}
namespace LISTEN_LIST {
std::mutex change_mutex;
std::vector<listen_mgr> listen_list_mgr;
}
namespace WAITING_MSG {
std::mutex waiting_for_ack;
}

in_port_t get_port(IP::packet& pckt)
{
    return ((tcphdr*)pckt.payload)->th_sport;
}

bool check_SYN(tcphdr& hdr)
{
    return hdr.syn && (!hdr.ack);
}

bool check_SYN_ACK(tcphdr& hdr)
{
    return hdr.syn && hdr.ack;
}
bool check_ACK(tcphdr& hdr)
{
    return hdr.ack;
}
bool check_FIN(tcphdr& hdr)
{
    return hdr.fin;
}

void handle_SYN_RECV(TCB& task, sockaddr_in* mgr)
{
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    BIND::bind_list.find(task.conn_fd)->second.another_seq_init = task.hdr.th_seq;
    BIND::bind_list.find(task.conn_fd)->second.another_present_seq = task.hdr.th_seq + 1;
    hdr.syn = 1;
    hdr.ack = 1;
    hdr.th_seq = BIND::bind_list.find(task.conn_fd)->second.my_seq_init;
    hdr.th_ack = task.hdr.th_seq + 1;
    hdr.th_sport = mgr->sin_port;
    hdr.th_dport = task.another_port;
    dbg_printf("\033[36m[HANDLE_SYN_RECV]\033[0m [dst_port: %d]\n", task.another_port);
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.check = 0;
    hdr.check = getChecksum(&hdr, 20);
    sendIPPacket(manager, mgr->sin_addr, task.another_ip, IPPROTO_TCP, &hdr, sizeof(hdr));
}
void handle_SYN_ACK_recv(fd_t sock_fd, IP::packet& pckt, tcphdr& in_hdr)
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
    memset(&hdr, 0, sizeof(hdr));
    hdr.ack = 1;
    hdr.th_seq = in_hdr.th_ack;
    hdr.th_ack = in_hdr.th_seq + 1;
    hdr.th_dport = in_hdr.th_sport;
    hdr.th_sport = in_hdr.th_dport;
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.check = 0;
    hdr.check = getChecksum(&hdr, 20);
    sendIPPacket(manager, pckt.header.ip_dst, pckt.header.ip_src, IPPROTO_TCP, &hdr, sizeof(hdr));
    // change sock_msg, full another_sock
    BIND::bind_list.find(sock_fd)->second.another_addr.sin_addr.s_addr = pckt.header.ip_src.s_addr;
    BIND::bind_list.find(sock_fd)->second.another_addr.sin_port = in_hdr.th_sport;
}

void sendSYN(int fd, sockaddr_in end_point, const sockaddr* dst_addr)
{
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
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
void send_ACK(fd_t fd)
{
    auto msg = BIND::bind_list.find(fd)->second;
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ack = 1;
    hdr.th_seq = msg.present_seq;
    hdr.th_ack = msg.another_present_seq;
    hdr.th_sport = msg.addr.sin_port;
    hdr.th_dport = msg.another_addr.sin_port;
    hdr.th_win = 65535;
    hdr.check = 0;
    change_tcphdr_to_net(hdr);
    hdr.check = getChecksum(&hdr, sizeof(hdr));
    sendIPPacket(manager, msg.addr.sin_addr, msg.another_addr.sin_addr, IPPROTO_TCP, &hdr, sizeof(hdr));
}
void send_FIN(fd_t fd)
{
    auto msg = BIND::bind_list.find(fd)->second;
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.fin = 1;
    hdr.th_seq = msg.present_seq;
    hdr.th_ack = msg.another_present_seq;
    hdr.th_sport = msg.addr.sin_port;
    hdr.th_dport = msg.another_addr.sin_port;
    hdr.th_win = 65535;
    hdr.check = 0;
    change_tcphdr_to_net(hdr);
    hdr.check = getChecksum(&hdr, sizeof(hdr));
    sendIPPacket(manager, msg.addr.sin_addr, msg.another_addr.sin_addr, IPPROTO_TCP, &hdr, sizeof(hdr));
}
void send_FINACK(fd_t fd)
{
    auto msg = BIND::bind_list.find(fd)->second;
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.fin = 1;
    hdr.ack = 1;
    hdr.th_seq = msg.present_seq;
    hdr.th_ack = msg.another_present_seq;
    hdr.th_sport = msg.addr.sin_port;
    hdr.th_dport = msg.another_addr.sin_port;
    hdr.th_win = 65535;
    hdr.check = 0;
    change_tcphdr_to_net(hdr);
    hdr.check = getChecksum(&hdr, sizeof(hdr));
    sendIPPacket(manager, msg.addr.sin_addr, msg.another_addr.sin_addr, IPPROTO_TCP, &hdr, sizeof(hdr));
}

int sendWrite(fd_t fildes, size_t nbyte, const void* buf, const std::string& type)
{
    tcphdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    u_char packet[sizeof(hdr) + nbyte];
    auto& msg = BIND::bind_list.find(fildes)->second;
    msg.last_len = nbyte;
    hdr.th_seq = msg.present_seq;
    hdr.th_ack = msg.another_present_seq;
    hdr.th_sport = msg.addr.sin_port;
    hdr.th_dport = msg.another_addr.sin_port;
    hdr.th_win = 65535;
    change_tcphdr_to_net(hdr);
    hdr.th_sum = 0;
    hdr.th_sum = getChecksum(&hdr, sizeof(hdr));
    memcpy(packet, &hdr, sizeof(hdr));
    memcpy(packet + sizeof(hdr), buf, nbyte);
    return 0;
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
    // len contains TCP hdr and content
    tcphdr hdr = *(tcphdr*)(pckt.payload);
    if (getChecksum(&hdr, sizeof(hdr)) != 0) {
        dbg_printf("\033[31m[TCP_handler ERROR] [getChecksum error]\033[0m\n");
        return -1;
    }
    dbg_printf("\033[32m[TCP_handler] [getChecksum success]\033[0m\n");
    change_tcphdr_to_host(hdr);
    ip_addr sock_ip = pckt.header.ip_dst;
    in_port_t sock_port = hdr.th_dport;
    ip_addr another_ip = pckt.header.ip_src;
    in_port_t another_port = hdr.th_sport;
    Device* dev_ptr = manager.findDevice(sock_ip);
    if (dev_ptr == NULL) {
        dbg_printf("\033[31m[TCP_handler ERROR]\033[0m Something is wrong, I don't have this IP!\n");
        return -1;
    }
    sockaddr_in sock, another_sock;
    sock.sin_addr = sock_ip;
    sock.sin_port = sock_port;
    another_sock.sin_addr = another_ip;
    another_sock.sin_port = another_port;
    dbg_printf("\033[36m[DEBUG INFO]\033[0m [src_port: %d] [dst_port: %d]\n", another_port, sock_port);
    fd_t sock_fd = BIND::findFdBySock(sock, another_sock);
    dbg_printf("\033[31m[SOCK_FD]\033[0m%d \033[31m[SYN]\033[0m %d \033[31m[ACK]\033[0m %d\n", sock_fd, hdr.syn, hdr.ack);
    if (check_SYN(hdr)) {
        if (sock_fd > 0) {
            dbg_printf("\033[31m[TCP_handler ERROR]\033[0m A connected socket received a SYN, and a RST will be sent\n");
            //not implemented handle RST
            return 0;
        }
        LISTEN_LIST::change_mutex.lock();
        for (auto& item : LISTEN_LIST::listen_list_mgr) {
            if (item.sock->sin_addr.s_addr == pckt.header.ip_dst.s_addr && (item.sock->sin_port == hdr.th_dport)) {
                item.listen_list.push_back(TCB(-1, pckt.header.ip_src, another_port, hdr));
                LISTEN_LIST::change_mutex.unlock();
                return 0;
            }
        }
        LISTEN_LIST::change_mutex.unlock();
        dbg_printf("\033[32m[INFO] [TCP_handler] [SYN]\033[0m This IP is not listening, \
            and this packet will be dropped! \n");
        return -1;
    }
    if (sock_fd < 0) {
        dbg_printf("\033[31m[TCP_handler ERROR]\033[0m No such fd!\n");
        return -1;
    }
    sock_handler(sock_fd, pckt, len, hdr);
    return 0;
}

int sock_handler(fd_t sock_fd, IP::packet& pckt, int len, tcphdr& hdr)
{
    DFA::dfa_status& status = DFA::status_list.find(sock_fd)->second;
    std::unique_lock<std::mutex> lk(ack_mutex);
    if (check_SYN_ACK(hdr)) {
        handle_SYN_ACK_recv(sock_fd, pckt, hdr);
        lk.unlock();
        cv.notify_all();
        return 0;
    } else if (check_ACK(hdr)) {
        if (check_FIN(hdr)) {
            // fin-ack
            if (status == DFA::CLOSING) {
                status = DFA::TIME_WAIT;
                cv_close.notify_all();
            } else if (status == DFA::FIN_WAIT_1) {
                status = DFA::FIN_WAIT_2;
                cv_close.notify_all();
            } else if (status == DFA::LAST_ACK) {
                cv_close.notify_all();
            }
        }
        if (status == DFA::SYN_RCVD) {
            // fill another_sock
            BIND::bind_list.find(sock_fd)->second.another_addr.sin_addr.s_addr = pckt.header.ip_src.s_addr;
            BIND::bind_list.find(sock_fd)->second.another_addr.sin_port = hdr.th_sport;
            //change status to estab
            DFA::change_status(sock_fd, DFA::ESTAB);
            lk.unlock();
            cv.notify_all();
            return 0;
        } else {
            if (hdr.th_ack != BIND::bind_list.find(sock_fd)->second.present_seq + BIND::bind_list.find(sock_fd)->second.last_len) {
                dbg_printf("\033[31m[sock_handler ERROR]\033[0m Incorrect ACK!\n");
                return -1;
            }
            BIND::bind_list.find(sock_fd)->second.present_seq += BIND::bind_list.find(sock_fd)->second.last_len;
            lk.unlock();
            cv.notify_all();
            return 0;
        }
    } else if (check_FIN(hdr)) {
        BIND::bind_list.find(sock_fd)->second.another_present_seq += 1;
        send_FINACK(sock_fd);
        if (status == DFA::ESTAB) {
            status = DFA::CLOSE_WAIT;
        } else if (status == DFA::FIN_WAIT_2) {
            status = DFA::TIME_WAIT;
            lk.unlock();
            cv_close.notify_all();
        } else if (status == DFA::FIN_WAIT_1) {
            status = DFA::CLOSING;
            cv_close.notify_all();
        }
        return 0;
    } else {
        if (status == DFA::ESTAB) {
            std::unique_lock<std::mutex> lk(read_mutex);
            u_char* content = (u_char*)pckt.payload + 20;
            auto& msg = BIND::bind_list.find(sock_fd)->second;
            for (int i = 0; i < len - 20; ++i) {
                msg.buffer.push_back(content[i]);
            }
            lk.unlock();
            cv_read.notify_all();
            return 0;
        }
    }
    return -1;
}

fd_t __wrap_socket(int domain, int type, int protocol)
{
    if (domain == PF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP) {
        for (int i = MY_FD_MAX; i >= MY_FD_MIN; --i) {
            if (FD::allovated_fds.find(i) == FD::allovated_fds.end()) {
                DFA::status_mutex.lock();
                DFA::status_list[i] = DFA::CLOSED;
                DFA::status_mutex.unlock();
                FD::allovated_fds.insert(i);
                assert(BIND::bind_list.find(i) == BIND::bind_list.end());
                BIND::bind_list[i] = sock_msg();
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
        BIND::bind_list[socket].is_listening = 1;
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
                    TCB& task = item.listen_list[0];
                    task.conn_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
                    BIND::bind_list[task.conn_fd] = sock_msg();
                    BIND::bind_list[task.conn_fd].addr = BIND::bind_list[socket].addr;
                    BIND::bind_list[task.conn_fd].another_addr.sin_family = AF_INET;
                    BIND::bind_list[task.conn_fd].another_addr.sin_addr.s_addr = task.another_ip.s_addr;
                    BIND::bind_list[task.conn_fd].another_addr.sin_port = task.another_port;
                    BIND::bind_list.find(task.conn_fd)->second.another_seq_init = task.hdr.th_seq;
                    change_status(task.conn_fd, DFA::SYN_RCVD);
                    handle_SYN_RECV(task, item.sock);
                    item.listen_list.erase(item.listen_list.begin());
                    LISTEN_LIST::change_mutex.unlock();
                    std::unique_lock<std::mutex> lk(ack_mutex);
                    while (1) {
                        if (cv.wait_for(lk, 1s, [&] { return DFA::status_list.find(task.conn_fd)->second == DFA::ESTAB; })) {
                            dbg_printf("\033[32m[ACCEPT INFO]\033[0m ACCEPT complete!\n");
                            break;
                        } else {
                            handle_SYN_RECV(task, item.sock);
                            continue;
                        }
                    }
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
    // in_port_t serverPort = ((sockaddr_in*)address)->sin_port;
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
    BIND::bind_list[socket].addr = end_point;
    DFA::change_status(socket, DFA::SYN_SENT);
    std::unique_lock<std::mutex> lk(ack_mutex);
    while (1) {
        if (cv.wait_for(lk, 1s, [&] { return DFA::status_list.find(socket)->second == DFA::ESTAB; })) {
            // send_ACK(socket);
            dbg_printf("\033[32m[CONNECT INFO]\033[0m CONNECT complete!\n");
            break;
        } else {
            dbg_printf("\033[31m[CONNECT WARNING]\033[0m Retransmitting\n");
            sendSYN(socket, end_point, address);
            continue;
        }
    }
    return 0;
}

ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte)
{
    int retrans = 0;
    if (BIND::bind_list.find(fildes) == BIND::bind_list.end()) {
        dbg_printf("\033[31m[WRITE ERROR]\033[0m Please use an active socket!\n");
        return 0;
    }
    if (DFA::status_list.find(fildes)->second != DFA::ESTAB) {
        dbg_printf("\033[31m[WRITE ERROR]\033[0m Please use an active socket!\n");
        return 0;
    }
    auto& msg = BIND::bind_list.find(fildes)->second;
    sendWrite(fildes, nbyte, buf, "First");
    msg.wait_for_ack = 1;
    std::unique_lock<std::mutex> lk(ack_mutex);
    while (1) {
        if (cv.wait_for(lk, 5s, [&] { return !msg.wait_for_ack; })) {
            dbg_printf("\033[32m[WRITE COMPLETE]\033[0m]\n");
            break;
        } else {
            sendWrite(fildes, nbyte, buf, "Retrans");
            retrans += 1;
            dbg_printf("\033[32m[WRITE INFO]\033[0m Retransmission time %d\n", retrans);
            if (retrans >= retrans_num) {
                lk.unlock();
                dbg_printf("\033[31m[WRITE ERROR]\033[0m] retransmission failed\n");
                return 0;
            }
            continue;
        }
    }
    return nbyte;
}

ssize_t __wrap_read(int fildes, void* buf, size_t nbyte)
{
    if (BIND::bind_list.find(fildes) == BIND::bind_list.end()) {
        dbg_printf("\033[31m[READ ERROR]\033[0m No such fd");
        return 0;
    }
    auto& msg = BIND::bind_list.find(fildes)->second;
    std::unique_lock<std::mutex> lk(read_mutex);
    cv_read.wait(lk, [&] { return msg.buffer.size() >= nbyte; });
    for (int _ = 0; _ < nbyte; ++_) {
        ((u_char*)buf)[_] = msg.buffer[0];
        msg.buffer.erase(msg.buffer.begin());
    }
    return nbyte;
}

int __wrap_close(int fildes)
{
    if (BIND::bind_list.find(fildes) == BIND::bind_list.end()) {
        dbg_printf("\033[31m[CLOSE ERROR]\033[0m No such fd!\n");
    }
    send_FIN(fildes);
    std::unique_lock<std::mutex> lk(fin_mutex);
    for (int i = retrans_num; i >= 0; --i) {
        if (cv_close.wait_for(lk, 1s, [&] { return DFA::status_list.find(fildes)->second == DFA::FIN_WAIT_2 || DFA::status_list.find(fildes)->second == DFA::CLOSING; })) {
            break;
        } else {
            send_FIN(fildes);
            continue;
        }
    }
    cv_close.wait(lk, [&] { return DFA::status_list.find(fildes)->second == DFA::TIME_WAIT; });
    std::this_thread::sleep_for(2s); // MSL
    delete_all(fildes);
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

void delete_all(fd_t fd)
{
    in_port_t end_point_port = BIND::bind_list.find(fd)->second.addr.sin_port;
    in_addr end_point_ip = BIND::bind_list.find(fd)->second.addr.sin_addr;
    Device* dev_ptr = manager.findDevice(end_point_ip);
    dev_ptr->port_mutex.lock();
    dev_ptr->empty_port[end_point_port] = 0;
    dev_ptr->port_mutex.unlock();
    BIND::bind_list.erase(BIND::bind_list.find(fd));
    DFA::status_mutex.lock();
    DFA::status_list.erase(DFA::status_list.find(fd));
    DFA::status_mutex.unlock();
    LISTEN_LIST::change_mutex.lock();
    for (auto iter = LISTEN_LIST::listen_list_mgr.begin(); iter != LISTEN_LIST::listen_list_mgr.end(); ++iter) {
        if (iter->mgr_fd == fd) {
            LISTEN_LIST::listen_list_mgr.erase(iter);
            break;
        }
    }
    LISTEN_LIST::change_mutex.unlock();
    FD::allovated_fds.erase(FD::allovated_fds.find(fd));
}