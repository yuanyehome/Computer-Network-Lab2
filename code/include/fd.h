#ifndef FD_H
#define FD_H
#include <limits.h>
#include <set>
namespace FD {
const int MY_FD_MIN = 798515;
const int MY_FD_MAX = INT_MAX;
std::set<int> allovated_fds;
bool contain_my_fd(int fd)
{
    return (fd >= MY_FD_MIN && fd <= MY_FD_MAX);
}
}
#endif