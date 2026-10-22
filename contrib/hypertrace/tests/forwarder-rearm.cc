/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
using namespace dtraced;

static int fail_kq = -1;
extern "C" int __real_kevent(int, const struct kevent *, int,
    struct kevent *, int, const struct timespec *);
extern "C" int
__wrap_kevent(int kq, const struct kevent *changes, int count,
    struct kevent *events, int nevents, const struct timespec *timeout)
{
    if (kq == fail_kq && count == 1 &&
        changes[0].filter == EVFILT_WRITE &&
        (changes[0].flags & EV_ENABLE) != 0 &&
        (changes[0].flags & EV_ADD) == 0) {
        fail_kq = -1;
        errno = EIO;
        return -1;
    }
    return __real_kevent(kq, changes, count, events, nevents, timeout);
}

int main()
{
    char path[] = "/tmp/hypertrace-rearm.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    dir outbound(path, nullptr);
    state s{};
    s.outbounddir = &outbound;
    int kq = kqueue(), sv[2], consumer_pair[2];
    assert(kq >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, consumer_pair) == 0);
    s.kq_hdl = kq;
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_KILL;
    auto *client = new client_fd(kq, sv[0], hello);
    hello.kind = DTRACED_KIND_CONSUMER;
    hello.subs = DTD_SUB_READDATA;
    client_fd consumer(kq, consumer_pair[0], hello);
    assert(client->enable_write(client));
    s.sockfds.insert(client);
    dtraced_hdr_t hdr{};
    hdr.msg_type = DTRACED_MSG_KILL;
    hdr.kill.pid = 123;
    hdr.kill.vmid = 1;
    hdr.kill.epoch = 42;
    hdr.kill.source_id[0] = 0x42;
    unsigned char unused = 0;
    client_request request(s, hdr, &unused, 0, &consumer);
    fail_kq = kq;
    assert(!request.handle());
    assert(client->retired.load() && s.sockfds.empty());
    assert(s.deadfds.find(client) != s.deadfds.end());
    assert(s.joblist.size() == 1);
    assert(outbound.source_revoked(hdr.kill.source_id) == 1);
    for (job *pending : s.joblist)
        delete pending;
    s.joblist.clear();
    s.deadfds.clear();
    delete client;
    close(sv[1]); close(consumer_pair[1]);
    close(kq);
    assert(unlinkat(outbound.dirfd,
        ".kill.0001.000000000000002a.0000007b.42000000000000000000000000000000",
        0) == 0);
    assert(unlinkat(outbound.dirfd, ".handoff.lock", 0) == 0);
    assert(rmdir(path) == 0);
    puts("PASS: failed forwarder rearm retires socket after durable kill commit");
}
