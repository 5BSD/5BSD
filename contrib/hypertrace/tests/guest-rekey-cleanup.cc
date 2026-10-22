/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <poll.h>
#include <atomic>
#include <shared_mutex>
#include <thread>
#include <sys/wait.h>
#include <unordered_map>
#include <unordered_set>
#include <sys/types.h>
#include <unistd.h>

#define DTT_GET_VM_IDENTITY 1
#define DTT_CLEANUP_DTRACED 3
#define DTT_CLEANUP_APPLIED 24
#define DTT_SESSION_STOP 25
#define DTT_SESSION_STOPPED 26
#define DTT_GET_CLEANUP_STATE 3
#define DTT_CLEANUP_STATE_PENDING 1
#define DTT_CLEANUP_STATE_APPLIED 2
#define DTT_CLEANUP_STATE_SESSION_STOP 4
#define DTT_IDENTITY_FRESH_ACTIVE 16
#define HYPERTRACE_MAX_VMS 256
struct dtt_vm_identity {
    uint16_t vmid;
    uint16_t old_vmid;
    uint32_t flags;
    uint64_t epoch;
    uint64_t old_epoch;
};
struct dtt_cleanup_state {
    uint64_t delivery_id, epoch;
    uint16_t vmid, flags;
    uint32_t reserved;
};
struct dtt_entry_t {
    uint8_t event_kind;
    union {
        struct { uint64_t delivery_id; uint16_t vmid; uint64_t epoch; }
            cleanup;
    } u;
};

struct state {
    struct { int dirfd = 3; } child_directory;
    decltype(child_directory) *inbounddir = &child_directory;
    std::shared_timed_mutex launch_gate;
    std::atomic_bool cleanup_in_progress{false};
	std::condition_variable host_elf_cv;
    std::timed_mutex pidlistmtx;
    std::unordered_set<pid_t> pidlist;
    std::unordered_map<pid_t, int> pidfds;
    int dtt_fd = 9;
    std::atomic_int reexecs{0};
    void re_exec() { ++reexecs; }
};
static int signals_sent, last_fd, shutdowns, kill_error, waits;
static int applied_reports;
static int stopped_reports;
static int retired_children;
static bool retire_error;
static bool fake_retire_guest_child(int directory, pid_t pid) {
    assert(directory == 3 && pid == 123);
    ++retired_children;
    if (retire_error) { errno = EIO; return false; }
    return true;
}
static ssize_t fake_write(int fd, const void *buf, size_t length) {
    assert(fd == 9 && length == sizeof(dtt_entry_t));
    const auto *entry = static_cast<const dtt_entry_t *>(buf);
    assert((entry->event_kind == DTT_CLEANUP_APPLIED ||
        entry->event_kind == DTT_SESSION_STOPPED) &&
        entry->u.cleanup.vmid == 42 && entry->u.cleanup.epoch == 99 &&
        entry->u.cleanup.delivery_id == 456);
    if (entry->event_kind == DTT_SESSION_STOPPED) ++stopped_reports;
    else ++applied_reports;
    return static_cast<ssize_t>(length);
}
static int64_t now_ms;
static bool poll_timeout;
static dtt_vm_identity vm_identity = { 42, 0, 0, 99, 0 };
static dtt_cleanup_state stop_state = {456, 99, 42,
    DTT_CLEANUP_STATE_PENDING | DTT_CLEANUP_STATE_SESSION_STOP, 0};
static int fake_ioctl(int fd, unsigned long command,
    void *result) {
    assert(fd == 9);
    if (command == DTT_GET_VM_IDENTITY)
        *static_cast<dtt_vm_identity *>(result) = vm_identity;
    else {
        assert(command == DTT_GET_CLEANUP_STATE);
        *static_cast<dtt_cleanup_state *>(result) = stop_state;
    }
    return 0;
}
static int64_t dtraced_io_deadline_after(int64_t delta) {
    return now_ms + delta;
}
static int64_t dtraced_io_milliseconds() { return now_ms; }
static int fake_pdkill(int fd, int signal) {
    assert(signal == SIGKILL);
    ++signals_sent;
    last_fd = fd;
    if (kill_error != 0) { errno = kill_error; return -1; }
    return 0;
}
static void fake_broadcast_shutdown(state &) { ++shutdowns; }
static int fake_poll(struct pollfd *fds, unsigned int count, int timeout) {
    assert(count == 1 && fds[0].fd == 42 && timeout > 0);
    if (poll_timeout) { now_ms += timeout; return 0; }
    fds[0].revents = POLLHUP;
    return 1;
}
static int fake_pdwait(int fd, int *status, int options, void *, void *) {
    assert(fd == 42 && options == WEXITED);
    *status = 0;
    ++waits;
    return 0;
}
#define pdkill fake_pdkill
#define poll fake_poll
#define pdwait fake_pdwait
#define ioctl fake_ioctl
#define write fake_write
#define broadcast_shutdown(s) fake_broadcast_shutdown(s)
#define retire_guest_child fake_retire_guest_child
#define WARN(...) ((void)0)
#define ERR(...) ((void)0)
#include "guest-rekey-cleanup.inc"
#undef ERR
#undef WARN
#undef broadcast_shutdown
#undef retire_guest_child
#undef pdwait
#undef ioctl
#undef write
#undef poll
#undef pdkill

int main() {
    state s;
    s.pidlist.insert(123);
    s.pidfds.emplace(123, 42);
    dtt_cleanup(&s);
    assert(signals_sent == 1 && last_fd == 42 && waits == 1 &&
        retired_children == 1 &&
        s.reexecs == 1 && shutdowns == 0 &&
        s.cleanup_in_progress.load());
    s.pidlist.insert(124);
    s.pidfds.clear();
    dtt_cleanup(&s);
    assert(signals_sent == 1 && s.reexecs == 1 && shutdowns == 1 &&
        errno == EPROTO);
    s.pidlist.clear(); s.pidlist.insert(1);
    dtt_cleanup(&s);
    assert(signals_sent == 1 && s.reexecs == 1 && shutdowns == 2);
    s.pidlist.clear(); s.pidlist.insert(123);
    s.pidfds.emplace(123, 42);
    kill_error = EIO;
    dtt_cleanup(&s);
    assert(signals_sent == 2 && s.reexecs == 1 && shutdowns == 3);
    kill_error = ESRCH;
    dtt_cleanup(&s);
    assert(signals_sent == 3 && waits == 2 &&
        s.reexecs == 2 && shutdowns == 3);
    kill_error = 0;
    poll_timeout = true;
    dtt_cleanup(&s);
    assert(signals_sent == 4 && waits == 2 &&
        s.reexecs == 2 && shutdowns == 4 && errno == ETIMEDOUT);
    dtt_entry_t cleanup = { DTT_CLEANUP_DTRACED,
        { { 456, 42, 99 } } };
    vm_identity.epoch = 100;
    dtt_cleanup_event(&s, cleanup);
    assert(signals_sent == 4 && shutdowns == 5 && errno == EPROTO);
    vm_identity.epoch = 99;
    cleanup.u.cleanup.delivery_id = 0;
    dtt_cleanup_event(&s, cleanup);
    assert(signals_sent == 4 && shutdowns == 6 && errno == EPROTO);
    cleanup.u.cleanup.delivery_id = 456;
    poll_timeout = false;
    dtt_cleanup_event(&s, cleanup);
    assert(signals_sent == 5 && waits == 3 && applied_reports == 1 &&
        s.reexecs == 3 && shutdowns == 6);
    state concurrent;
    std::atomic_bool launch_started{false}, release_launch{false};
    std::thread launcher([&] {
        std::shared_lock gate(concurrent.launch_gate);
        launch_started.store(true);
        while (!release_launch.load())
            std::this_thread::yield();
    });
    while (!launch_started.load())
        std::this_thread::yield();
    std::thread cleaner([&] { dtt_cleanup(&concurrent); });
    while (!concurrent.cleanup_in_progress.load())
        std::this_thread::yield();
    assert(concurrent.reexecs == 0);
    release_launch.store(true);
    launcher.join();
    cleaner.join();
    assert(concurrent.reexecs == 1);

    /* A fresh-session coordinator can stop without re-exec or a wire ACK. */
    state fresh;
    fresh.pidlist.insert(123);
    fresh.pidfds.emplace(123, 42);
    const int reports_before = applied_reports;
    const int shutdowns_before = shutdowns;
    assert(quiesce_guest_tracing(&fresh, now_ms + 10000));
    assert(fresh.cleanup_in_progress.load() && fresh.reexecs == 0 &&
        applied_reports == reports_before && shutdowns == shutdowns_before);

    /* Admission lock contention consumes the same stop budget. */
    state launch_blocked;
    std::shared_lock held_launch(launch_blocked.launch_gate);
    bool stopped = true;
    int stop_errno = 0;
    const int signals_before = signals_sent;
    std::thread stop_launch([&] {
        stopped = quiesce_guest_tracing(&launch_blocked, now_ms + 10);
        stop_errno = errno;
    });
    stop_launch.join();
    assert(!stopped && stop_errno == ETIMEDOUT &&
        launch_blocked.cleanup_in_progress.load() &&
        signals_sent == signals_before && applied_reports == reports_before);
    held_launch.unlock();

    /* A busy child registry must not bypass that deadline either. */
    state registry_blocked;
    std::unique_lock held_registry(registry_blocked.pidlistmtx);
    std::thread stop_registry([&] {
        stopped = quiesce_guest_tracing(&registry_blocked, now_ms + 10);
        stop_errno = errno;
    });
    stop_registry.join();
    assert(!stopped && stop_errno == ETIMEDOUT &&
        registry_blocked.cleanup_in_progress.load() &&
        signals_sent == signals_before && applied_reports == reports_before);
    held_registry.unlock();

    /* Failure leaves admission closed, emits no ACK, and permits an exact retry. */
    retire_error = true;
    assert(!quiesce_guest_tracing(&fresh, now_ms + 10000) && errno == EIO);
    assert(fresh.cleanup_in_progress.load() && fresh.reexecs == 0 &&
        applied_reports == reports_before && shutdowns == shutdowns_before);
    retire_error = false;
    assert(quiesce_guest_tracing(&fresh, now_ms + 10000));
    assert(!quiesce_guest_tracing(&fresh, now_ms) && errno == ETIMEDOUT);
    assert(!quiesce_guest_tracing(nullptr, now_ms + 1) && errno == EINVAL);
    cleanup.event_kind = DTT_SESSION_STOP;
    assert(dtt_session_stop_event(&fresh, cleanup));
    assert(stopped_reports == 1 && fresh.reexecs == 0);
    stop_state.delivery_id++;
    assert(!dtt_session_stop_event(&fresh, cleanup) && errno == EPROTO);
    assert(stopped_reports == 1);
    stop_state.delivery_id--;
    stop_state.flags = DTT_CLEANUP_STATE_PENDING;
    assert(!dtt_session_stop_event(&fresh, cleanup) && errno == EPROTO);
    assert(stopped_reports == 1);
    stop_state.flags |= DTT_CLEANUP_STATE_SESSION_STOP;
    retire_error = true;
    assert(!dtt_session_stop_event(&fresh, cleanup) && errno == EIO);
    assert(stopped_reports == 1 && fresh.reexecs == 0);
    retire_error = false;
    assert(dtt_session_stop_event(&fresh, cleanup));
    assert(stopped_reports == 2 && fresh.reexecs == 0);
    vm_identity.flags = DTT_IDENTITY_FRESH_ACTIVE;
    vm_identity.old_vmid = 41;
    vm_identity.old_epoch = 98;
    assert(dtt_session_stop_event(&fresh, cleanup));
    assert(stopped_reports == 3 && fresh.reexecs == 0);
    puts("PASS: bounded guest-session quiesce and exact stop acknowledgment");
}
