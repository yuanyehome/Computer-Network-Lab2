#ifndef TCP_H
#define TCP_H
#include "routeTable.h"

// 每个IP地址要维护一个port占用列表；
// connect会优先采用bind的结果（IP与port）；
// bind应该检查IP是否存在，如果不存在要bind失败，IP与port均置为0；port不对也会bind失败；只传了IP但是port为0那么随机指定。
// TCP协议listen前似乎一定要指定端口
struct TCB {
    fd_t conn_fd;
    ip_addr another_ip;
    in_port_t another_port;
    tcphdr hdr;
    TCB(fd_t conn_fd_, ip_addr another_ip_, in_port_t another_port_, tcphdr& hdr_)
        : conn_fd(conn_fd_)
        , another_port(another_port_)
        , hdr(hdr_)
    {
        another_ip.s_addr = another_ip_.s_addr;
    }
};
struct listen_mgr {
    fd_t mgr_fd;
    sockaddr_in* sock;
    std::vector<TCB> listen_list;
    listen_mgr(fd_t fd, sockaddr_in* sock_)
        : mgr_fd(fd)
        , sock(sock_)
    {
    }
};
struct sock_msg {
    sockaddr_in addr;
    sockaddr_in another_addr;
    int my_seq_init;
    int another_seq_init;
    sock_msg()
        : another_seq_init(-1)
    {
        my_seq_init = rand() % 65536;
    };
};
namespace BIND {
extern std::mutex msg_mutex;
extern std::map<fd_t, sock_msg> bind_list;
fd_t findFdBySock(sockaddr_in sock);
}
namespace LISTEN_LIST {
extern std::mutex change_mutex;
extern std::vector<listen_mgr> listen_list_mgr;
}

/**
 * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/socket.html)
 */
fd_t __wrap_socket(int domain, int type, int protocol);

/**
 * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/bind.html)
 */
int __wrap_bind(fd_t socket, const struct sockaddr* address,
    socklen_t address_len);

/**
 * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/listen.html)
 */
int __wrap_listen(int socket, int backlog);

/**
 * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/connect.html)
 */
int __wrap_connect(int socket, const struct sockaddr* address,
    socklen_t address_len);

/**
 * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/accept.html)
 */
int __wrap_accept(int socket, struct sockaddr* address,
    socklen_t* address_len);

/**
 * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/read.html)
 */
ssize_t __wrap_read(int fildes, void* buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/write.html)
 */
ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte);

/**
 * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/close.html)
 */
int __wrap_close(int fildes);

/** 
 * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
 * 9699919799/functions/getaddrinfo.html)
 */
int __wrap_getaddrinfo(const char* node, const char* service,
    const struct addrinfo* hints,
    struct addrinfo** res);
int __wrap__freeaddrinfo(addrinfo* ai);

int TCP_handler(IP::packet& pckt, int len);

void handle_SYN_RECV(TCB& task, sockaddr_in* mgr);
void handle_SYN_ACK_recv(fd_t sock_fd, IP::packet& pckt);

void change_tcphdr_to_host(tcphdr& hdr);

void change_tcphdr_to_net(tcphdr& hdr);

bool check_SYN(IP::packet& pckt, int len);
bool check_SYN_ACK(IP::packet& pckt, int len);

//

#endif