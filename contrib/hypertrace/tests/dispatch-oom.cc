/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <new>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_job.h"
#include "dtraced_state.h"

using namespace dtraced;
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
    int kq = kqueue(); assert(kq >= 0);
    dtd_initmsg_t hello{};
    auto *client = new client_fd(kq, sv[0], hello);
    state s{};
    struct kevent event{};
    event.ident = sv[0];
    event.udata = client;

    event.filter = EVFILT_READ;
    for (int n : {0, 1}) {
        fail_after = n;
        assert(!s.dispatch_event(event));
        fail_after = -1;
        assert(errno == ENOMEM);
        assert(s.dispatched_jobs.empty() && client->is_dead());
    }
    assert(s.dispatch_event(event));
    assert(s.dispatched_jobs.size() == 1);
    delete s.dispatched_jobs.front();
    s.dispatched_jobs.clear();
    assert(client->is_dead());

    auto *queued = new job(SEND_INFO, client);
    s.joblist.push_back(queued);
    event.filter = EVFILT_WRITE;
    fail_after = 0;
    assert(s.dispatch_event(event));
    fail_after = -1;
    assert(s.joblist.empty() && s.dispatched_jobs.size() == 1);
    delete s.dispatched_jobs.front();
    s.dispatched_jobs.clear();
    assert(client->is_dead());

    delete client;
    close(sv[1]);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    auto *retiring = new client_fd(kq, sv[0], hello);
    state shutdown_state{};
    shutdown_state.kq_hdl = kq;
    shutdown_state.sockfds.insert(retiring);
    fail_after = 0;
    shutdown_state.kill_socket(retiring);
    fail_after = -1;
    assert(shutdown_state.shutdown.load() == 1);
    assert(shutdown_state.sockfds.count(retiring) == 1);
    assert(shutdown_state.deadfds.empty());
    assert(retiring->retired.load());
    shutdown_state.sockfds.clear();
    fail_after = 0;
    delete retiring;
    fail_after = -1;
    close(sv[1]);
    close(kq);
    puts("PASS: dispatch failures preserve references and queue ownership; retirement OOM retains shutdown ownership");
}
