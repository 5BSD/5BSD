/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static int test_clock_gettime(clockid_t, struct timespec *);
static int test_poll(struct pollfd *, nfds_t, int);
#define clock_gettime test_clock_gettime
#define poll test_poll
#include "dtrace_identifiers.h"
#undef clock_gettime
#undef poll
static int fail_clock, poll_calls, short_poll_once;
static int test_clock_gettime(clockid_t clock, struct timespec *now) {
    if (fail_clock) { errno = EIO; return -1; }
    return clock_gettime(clock, now);
}
static int test_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (fail_clock) { poll_calls++; errno = EINVAL; return -1; }
    if (short_poll_once) { short_poll_once = 0; return 0; }
    return poll(fds, count, timeout);
}
static void *fragment(void *arg) {
    int fd = *(int *)arg; size_t count = 2;
    unsigned char count_wire[8];
    unsigned char payload[32]; memset(payload, 0x71, sizeof(payload));
    dtraced_wire_put_u64(count_wire, count);
    for (size_t i = 0; i < sizeof(count_wire); ++i)
        assert(write(fd, count_wire + i, 1) == 1);
    for (size_t i = 0; i < sizeof(payload); ++i) assert(write(fd, payload + i, 1) == 1);
    close(fd); return NULL;
}
int main(void) {
    alarm(10);
    unsigned char byte;
    int64_t deadline = dtraced_io_deadline_after(1000);
    assert(dtrace_ident_read_exact(-1, &byte, 1, -1) == -1 && errno == EINVAL);
    fail_clock = 1;
    assert(dtrace_ident_read_exact(-1, &byte, 1, deadline) == -1 && errno == EIO);
    assert(poll_calls == 0);
    fail_clock = 0;
    int ready_pipe[2];
    assert(pipe(ready_pipe) == 0);
    byte = 0x5a;
    assert(write(ready_pipe[1], &byte, 1) == 1);
    byte = 0;
    short_poll_once = 1;
    assert(dtrace_ident_read_exact(ready_pipe[0], &byte, 1,
        dtraced_io_milliseconds() + (int64_t)INT32_MAX + 1000) == 0);
    assert(byte == 0x5a && short_poll_once == 0);
    close(ready_pipe[0]); close(ready_pipe[1]);
    for (int socket = 0; socket < 2; ++socket) {
        int pair[2];
        assert((socket ? socketpair(AF_UNIX, SOCK_STREAM, 0, pair) : pipe(pair)) == 0);
        pthread_t writer; assert(pthread_create(&writer, NULL, fragment, &pair[1]) == 0);
        unsigned char *ids; size_t count;
        assert(dtrace_read_identifiers(pair[0], &ids, &count, 16, dtraced_io_milliseconds() + 1000) == 0);
        assert(count == 2); for (int i = 0; i < 32; ++i) assert(ids[i] == 0x71);
        free(ids); close(pair[0]); pthread_join(writer, NULL);
    }
    for (int test = 0; test < 4; ++test) {
        int pair[2]; assert(pipe(pair) == 0);
        uint64_t n = test == 0 ? 0 : test == 1 ? UINT64_MAX : 2;
        size_t count = 99;
        unsigned char count_wire[8];
        dtraced_wire_put_u64(count_wire, n);
        unsigned char *ids = (void *)1;
        if (test != 3) {
            assert(write(pair[1], count_wire, sizeof(count_wire)) ==
                sizeof(count_wire));
            if (test == 2) assert(write(pair[1], "x", 1) == 1);
            close(pair[1]);
        }
        assert(dtrace_read_identifiers(pair[0], &ids, &count, 16, dtraced_io_milliseconds() + 30) == -1);
        assert(ids == NULL && count == 0);
        if (test == 3) { assert(errno == ETIMEDOUT); close(pair[1]); }
        close(pair[0]);
    }
    for (int installed = 0; installed <= 1; ++installed) {
        int pair[2]; size_t moved;
        char ident[DTRACED_PROGIDENTLEN];
        memset(ident, 0x58, sizeof(ident));
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        assert(dtrace_write_launch_result(pair[0], installed, ident,
            sizeof(ident) - 1, dtraced_io_milliseconds() + 1000) == -1 &&
            errno == EINVAL);
        assert(dtrace_write_launch_result(pair[0], installed, ident,
            sizeof(ident), dtraced_io_milliseconds() + 1000) == 0);
        dtraced_launch_result_t report;
        unsigned char report_wire[DTRACED_LAUNCH_WIRE_SIZE];
        assert(dtraced_io_transfer(pair[1], report_wire,
            sizeof(report_wire), false,
            dtraced_io_milliseconds() + 1000, &moved) == 0);
        assert(dtraced_wire_decode_launch(&report, report_wire) == 0);
        assert(report.magic == DTRACED_LAUNCH_MAGIC &&
            report.installed == installed &&
            memcmp(report.source_ident, ident, sizeof(ident)) == 0);
        close(pair[0]); close(pair[1]);
    }
    puts("PASS: CLI identifier handshake and post-exec installation frame");
}
