// SPDX-License-Identifier: BSD-2-Clause
#include <sys/socket.h>
#include <poll.h>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include "dtraced_socket.h"

static int poll_calls;

extern "C" int
__wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    assert(fds != nullptr && count == 1 && timeout == INT_MAX);
    if (++poll_calls == 1)
        return 0; // One capped interval must not expire the full deadline.
    errno = ECANCELED;
    return -1;
}

int
main()
{
    int sockets[2];
    char byte = 0;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    auto budget = std::chrono::milliseconds(static_cast<int64_t>(INT_MAX) +
        1000);
    assert(!dtraced::socket_transfer(sockets[0], &byte, 1, false, budget));
    assert(errno == ECANCELED && poll_calls == 2);
    close(sockets[0]);
    close(sockets[1]);
    puts("PASS: long socket deadline uses bounded poll intervals");
}
