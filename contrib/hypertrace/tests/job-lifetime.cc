// SPDX-License-Identifier: BSD-2-Clause
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <vector>
#include "dtraced_connection.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
int main() {
	dtraced::state s{};
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
    c.kind = DTRACED_KIND_FORWARDER;
    c.vmid = 42;
    c.vm_epoch = 99;
    {
        dtraced::job kill(dtraced::KILL, &c);
        auto &target = kill.kill_get();
        target.pid = 123;
        target.vmid = 42;
        target.epoch = 99;
        target.source_id[0] = 0x42;
		assert(!kill.send_kill(s) && errno == ESTALE);
    }
    assert(c.can_reap());
    close(sv[1]);
}
