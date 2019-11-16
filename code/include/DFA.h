#ifndef DFA_H
#define DFA_H
#include "tcp.h"
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
namespace DFA {
extern std::map<fd_t, dfa_status> status_list;
}

#endif