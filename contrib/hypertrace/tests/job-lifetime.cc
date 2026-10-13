// SPDX-License-Identifier: BSD-2-Clause
#include <sys/socket.h>
#include <cassert>
#include <cstdlib>
#include <vector>
#include "dtraced_connection.h"
#include "dtraced_job.h"
int main() {
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    dtd_initmsg_t init {};
    dtraced::client_fd c(-1, sv[0], init);
    c.cleaned_up = true;
    assert(c.can_reap());
    {
        dtraced::job info(dtraced::SEND_INFO, &c);
        assert(!c.can_reap());
    }
    assert(c.can_reap());
    {
        dtraced::job cleanup(dtraced::CLEANUP, &c);
        cleanup.cleanup_get() = new dtraced::cleanup_job(100, std::string(1000, 'x'));
        assert(!c.can_reap());
    }
    assert(c.can_reap());
    close(sv[1]);
}
