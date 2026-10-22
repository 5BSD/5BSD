/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <new>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_job.h"
#include "dtraced_socket.h"
#include "dtraced_state.h"

static int fail_after = -1;
extern "C" void *__real__Znwm(size_t);
extern "C" void *__wrap__Znwm(size_t size)
{
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    return __real__Znwm(size);
}

int main()
{
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    dtd_initmsg_t hello{};
    dtraced::client_fd client(-1, sv[0], hello);
    dtraced::state state{};
    state.sockfds.insert(&client);
    {
        dtraced::job info(dtraced::SEND_INFO, &client);
        fail_after = 0;
        assert(!info.send_info(state));
        fail_after = -1;
        assert(errno == ENOMEM);
        assert(info.send_info(state));
        dtraced_hdr_t header{};
        assert(dtraced::socket_transfer(sv[1], &header, sizeof(header), false));
        assert(header.msg_type == DTRACED_MSG_INFO && header.info.count == 1);
        dtraced_infomsg_t item{};
        assert(dtraced::socket_transfer(sv[1], &item, sizeof(item), false));
    }
    assert(client.is_dead());
    state.sockfds.clear();
    close(sv[1]);
    puts("PASS: client-list allocation failure leaves connection usable and job reference balanced");
}
