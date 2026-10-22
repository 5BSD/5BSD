/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/wait.h>
#include <sys/procdesc.h>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <poll.h>
#include <thread>
#include <unistd.h>
#include "dtraced_state.h"
#include "dtraced_misc.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_io.h"
using namespace dtraced;
static pid_t child(bool running) {
    pid_t pid = fork(); assert(pid >= 0);
    if (pid == 0) {
        if (running) for (;;) pause();
        _exit(17);
    }
    return pid;
}
int main() {
    alarm(15);
    state s{};
    pid_t finished = child(false);
    timespec timeout{2, 0};
    int status = waitpid_timeout(finished, &timeout);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 17);
    assert(waitpid(finished, &status, WNOHANG) == -1 && errno == ECHILD);
    pid_t owned = child(true), owned_peer = child(true), foreground = child(true);
    timeout = {0, 20000000};
    assert(waitpid_timeout(owned, &timeout) == -1 && errno == ETIMEDOUT);
    s.pidlist.insert(owned);
    s.pidlist.insert(owned_peer);
    std::array<uint8_t, 16> source{};
    source[0] = 0x42;
    s.pid_sources.emplace(owned, source);
    s.pid_sources.emplace(owned_peer, source);
    std::thread manager(&state::manage_children, &s);
    std::thread reaper(&state::reap_children, &s);
    {
        std::lock_guard lk(s.killmtx);
        s.pids_to_kill.push({0, source}); s.pids_to_kill.push({1, source});
        s.pids_to_kill.push({getpid(), source}); s.pids_to_kill.push({foreground, source});
        auto wrong = source; wrong[0]++;
        s.pids_to_kill.push({owned, wrong});
        s.killcv.notify_all();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    assert(waitpid(owned, &status, WNOHANG) == 0);
    assert(waitpid(owned_peer, &status, WNOHANG) == 0);
    {
        std::lock_guard children(s.pidlistmtx);
        s.revoked_sources.insert(source);
    }
    {
        std::lock_guard lk(s.killmtx);
        s.pids_to_kill.push({finished, source});
        s.killcv.notify_all();
    }
    bool reaped = false;
    for (int i = 0; i < 400 && !reaped; ++i) {
        { std::lock_guard lk(s.pidlistmtx); reaped = s.pidlist.empty(); }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(reaped);
    assert(waitpid(owned, &status, WNOHANG) == -1 && errno == ECHILD);
    assert(waitpid(owned_peer, &status, WNOHANG) == -1 && errno == ECHILD);
    assert(waitpid(foreground, &status, WNOHANG) == 0);
    assert(kill(foreground, SIGTERM) == 0);
    timeout = {2, 0};
    status = waitpid_timeout(foreground, &timeout);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    { std::lock_guard lk(s.killmtx); s.shutdown.store(1); s.killcv.notify_all(); }
    manager.join(); reaper.join();

    /* Exercise fresh-session stop with real process descriptors, not PID
     * signaling substitutes. An unrelated process must keep running. */
    char path[] = "/tmp/hypertrace-session-stop.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    {
        dir inbound(path, nullptr);
        state fresh{};
        fresh.inbounddir = &inbound;
        int owned_fd, unrelated_fd;
        pid_t tracing = pdfork(&owned_fd, PD_CLOEXEC);
        assert(tracing >= 0);
        if (tracing == 0) for (;;) pause();
        pid_t unrelated = pdfork(&unrelated_fd, PD_CLOEXEC);
        assert(unrelated >= 0);
        if (unrelated == 0) for (;;) pause();
        fresh.pidlist.insert(tracing);
        fresh.pidfds.emplace(tracing, owned_fd);
        assert(quiesce_guest_tracing(&fresh,
            dtraced_io_deadline_after(2000)));
        assert(fresh.cleanup_in_progress.load());
        struct pollfd ended{owned_fd, POLLHUP, 0};
        assert(poll(&ended, 1, 0) == 1 && (ended.revents & POLLHUP));
        struct pollfd alive{unrelated_fd, POLLHUP, 0};
        assert(poll(&alive, 1, 0) == 0);
        /* Exact retry after child exit and ledger retirement is harmless. */
        assert(quiesce_guest_tracing(&fresh,
            dtraced_io_deadline_after(2000)));
        assert(poll(&alive, 1, 0) == 0);
        assert(pdkill(unrelated_fd, SIGKILL) == 0);
        assert(pdwait(unrelated_fd, &status, WEXITED, nullptr, nullptr) == 0);
        assert(close(unrelated_fd) == 0);
        assert(waitpid(unrelated, &status, 0) == unrelated || errno == ECHILD);
        fresh.pidfds.clear();
        fresh.pidlist.clear();
        fresh.inbounddir = nullptr;
        assert(close(owned_fd) == 0);
        assert(waitpid(tracing, &status, 0) == tracing || errno == ECHILD);
    }
    assert(rmdir(path) == 0);
    puts("PASS: owned-child termination/reaping, durable source-wide kill after target PID exit, foreground ownership and timeout handoff");
}
