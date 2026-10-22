/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <dev/dttransport/dttransport.h>
#include <atomic>
#include <cassert>
#include <cerrno>
struct state { std::atomic_int shutdown{0}; int dtt_fd = 9; };
static state s;
static dtt_cleanup_state stop{123, 11, 7,
    DTT_CLEANUP_STATE_PENDING | DTT_CLEANUP_STATE_APPLIED |
    DTT_CLEANUP_STATE_SESSION_STOP, 0};
static dtt_vm_identity identity{7, 0, 0, 11, 0};
static int sleeps, mode, ioctl_error;
static int fake_ioctl(int fd, unsigned long cmd, void *data) {
    assert(fd == 9);
    if (ioctl_error) { errno = ioctl_error; ioctl_error = 0; return -1; }
    if (cmd == DTT_GET_CLEANUP_STATE)
        *static_cast<dtt_cleanup_state *>(data) = stop;
    else {
        assert(cmd == DTT_GET_VM_IDENTITY);
        *static_cast<dtt_vm_identity *>(data) = identity;
    }
    return 0;
}
static int fake_usleep(unsigned usec) {
    assert(usec == 100000);
    assert(++sleeps <= 3);
    if (sleeps == 3) {
        if (mode == 1) s.shutdown.store(1);
        else identity = {8, 7, DTT_IDENTITY_FRESH_PENDING, 12, 11};
    }
    return 0;
}
#define ioctl fake_ioctl
#define usleep fake_usleep
#include "guest-fresh-wait.inc"
int main() {
    const auto expected = stop;
    ioctl_error = EINTR;
    assert(wait_guest_fresh_prepare(&s, expected) && sleeps == 3);
    identity.flags = DTT_IDENTITY_FRESH_READY;
    assert(wait_guest_fresh_prepare(&s, expected));
    identity.old_epoch++;
    assert(!wait_guest_fresh_prepare(&s, expected) && errno == ESTALE);
    identity.old_epoch--;
    stop.delivery_id++;
    assert(!wait_guest_fresh_prepare(&s, expected) && errno == ESTALE);
    stop = expected;
    identity = {7, 6, DTT_IDENTITY_FRESH_ACTIVE, 11, 10};
    sleeps = 0; mode = 1;
    assert(!wait_guest_fresh_prepare(&s, expected) && errno == ECANCELED && sleeps == 3);
    s.shutdown.store(0);
    ioctl_error = EIO;
    assert(!wait_guest_fresh_prepare(&s, expected) && errno == EIO);
    identity = {8, 7, DTT_IDENTITY_FRESH_PENDING, 11, 11};
    assert(!wait_guest_fresh_prepare(&s, expected) && errno == ESTALE);
}
