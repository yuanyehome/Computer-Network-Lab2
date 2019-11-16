#include "DFA.h"
#include "fd.h"
namespace DFA {
std::map<fd_t, dfa_status> status_list;
}
namespace BIND {
std::map<fd_t, sockaddr*> bind_list;
}
namespace LISTEN_LIST {
std::mutex is_open_mutex;
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

int TCP_handler(IP::packet& pckt, int len)
{
    if (check_SYN(pckt, len)) {
        LISTEN_LIST::is_open_mutex.lock();
        for (auto& item : LISTEN_LIST::listen_list_mgr) {
            if (item.sock->sin_addr.s_addr == pckt.header.ip_dst.s_addr) {
                in_port_t another_port = get_port(pckt);
                item.listen_list.push_back(TCB(-1, pckt.header.ip_src, another_port));
                LISTEN_LIST::is_open_mutex.unlock();
                return 0;
            }
        }
        LISTEN_LIST::is_open_mutex.unlock();
        dbg_printf("\033[32m[INFO] [TCP_handler] [SYN]\033[0m This IP is not listening, \
            and this packet will be dropped! \n");
    } else {
        // not implemented;
    }
}

fd_t __wrap_socket(int domain, int type, int protocol)
{
    if (domain == PF_INET && type == SOCK_STREAM && protocol == IPPROTO_TCP) {
        for (int i = FD::MY_FD_MAX; i >= FD::MY_FD_MIN; --i) {
            if (FD::allovated_fds.find(i) == FD::allovated_fds.end()) {
                DFA::status_list[i] = CLOSED;
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
        LISTEN_LIST::is_open_mutex.lock();
        LISTEN_LIST::listen_list_mgr.push_back(listen_mgr(socket, this_sock));
        LISTEN_LIST::is_open_mutex.unlock();
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
}