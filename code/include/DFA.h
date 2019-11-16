#ifndef DFA_H
#define DFA_H
#include "tcp.h"

namespace DFA {

enum dfa_status {
    CLOSED,
    LISTEN,
    SYN_RCVD,
    SYN_SENT,
    ESTAB,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_ACK,
    CLOSING,
    TIME_WAIT
};
std::mutex status_mutex;
extern std::map<fd_t, dfa_status> status_list;
int change_status(fd_t fd, dfa_status status);
}

#endif