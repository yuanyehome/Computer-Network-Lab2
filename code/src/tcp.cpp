#include "DFA.h"
#include "fd.h"
namespace DFA {
std::map<fd_t, dfa_status> status_list;
}
namespace BIND {
std::map<fd_t, sockaddr*> bind_list;
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
    return ((tcphdr*)pckt.payload)->syn;
}

void handle_SYN_RECV(TCB& task, sockaddr_in* mgr)
{
    tcphdr hdr;
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
    if (check_SYN(pckt, len)) {
        LISTEN_LIST::change_mutex.lock();
        for (auto& item : LISTEN_LIST::listen_list_mgr) {
            if (item.sock->sin_addr.s_addr == pckt.header.ip_dst.s_addr && (item.sock->sin_port == ((sockaddr_in*)pckt.payload)->sin_port)) {
                in_port_t another_port = get_port(pckt);
                item.listen_list.push_back(TCB(-1, pckt.header.ip_src, another_port));
                LISTEN_LIST::change_mutex.unlock();
                return 0;
            }
        }
        LISTEN_LIST::change_mutex.unlock();
        dbg_printf("\033[32m[INFO] [TCP_handler] [SYN]\033[0m This IP is not listening, \
            and this packet will be dropped! \n");
        return -1;
    } else {
        // not implemented;
    }
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
                sockaddr* tmp_sock = new sockaddr;
                memset(tmp_sock, 0, sizeof(sockaddr));
                BIND::bind_list[i] = tmp_sock;
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
    try {
        sockaddr* tmp_sock = new sockaddr;
        memcpy(tmp_sock, address, address_len);
        BIND::bind_list[socket] = tmp_sock;
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
        sockaddr_in* this_sock = (sockaddr_in*)BIND::bind_list[socket];
        if (this_sock->sin_addr.s_addr == 0 || this_sock->sin_port == 0) {
            dbg_printf("\033[31m[LISTEN ERROR]\033[0m Please specify IP address and port for listening\n");
            return -1;
        }
        LISTEN_LIST::change_mutex.lock();
        DFA::status_mutex.lock();
        LISTEN_LIST::listen_list_mgr.push_back(listen_mgr(socket, this_sock));
        DFA::status_list[socket] = DFA::LISTEN;
        DFA::status_mutex.unlock();
        LISTEN_LIST::change_mutex.unlock();
        // tell TCP_handler it can push item into listen_list;
        dbg_printf("\033[32m[INFO] [START LISTENING]\033[0m\n");
    } catch (const char* e) {
        dbg_printf("\033[31m[LISTEN ERROR]\033[0m e\n");
        return -1;
    }
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
                    sockaddr_in channel;
                    channel.sin_family = AF_INET;
                    channel.sin_addr.s_addr = task.another_ip.s_addr;
                    channel.sin_port = task.another_port;
                    __wrap_bind(task.conn_fd, (sockaddr*)(&channel), sizeof(channel));
                    change_status(task.conn_fd, DFA::SYN_RCVD);
                    handle_SYN_RECV(task, item.sock);
                    item.listen_list.erase(item.listen_list.begin());
                    LISTEN_LIST::change_mutex.unlock();
                    if (address != NULL) {
                        memcpy(address, &channel, sizeof(channel));
                        *address_len = sizeof(channel);
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
}