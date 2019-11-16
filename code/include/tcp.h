#ifndef TCP_H
#define TCP_H
#include "routeTable.h"

struct TCB {
    fd_t conn_fd;
    ip_addr another_ip;
    in_port_t another_port;
    TCB(fd_t conn_fd_, ip_addr another_ip_, in_port_t another_port_)
        : conn_fd(conn_fd_)
        , another_port(another_port_)
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
namespace BIND {
extern std::map<fd_t, sockaddr*> bind_list;
}
namespace LISTEN_LIST {
extern std::mutex is_open_mutex;
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

int TCP_handler(IP::packet& pckt, int len);

bool check_SYN(IP::packet& pckt, int len);

//

#endif