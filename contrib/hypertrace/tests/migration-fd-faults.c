/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "migration_session.h"
static int mode, calls, waits;
static short wait_events;
static size_t used;
static unsigned char bytes[64];
ssize_t __real_recv(int, void *, size_t, int);
ssize_t __real_send(int, const void *, size_t, int);
int __real_poll(struct pollfd *, nfds_t, int);
/* Modes 5-7 find the socket full or empty once, then fault the wait. */
ssize_t __wrap_send(int fd, const void *p, size_t n, int flags) {
    if (fd != 12345) return __real_send(fd, p, n, flags);
    assert(flags == (MSG_NOSIGNAL | MSG_DONTWAIT));
    ++calls;
    if (mode == 1 && calls == 1) { errno = EINTR; return -1; }
    if (mode >= 5 && calls == 1) { errno = EAGAIN; return -1; }
    if (mode == 2) return 0;
    if (mode == 3 || mode == 4) { errno = mode == 3 ? ENOSPC : 0; return -1; }
    n = n > 3 ? 3 : n; assert(used + n <= sizeof(bytes));
    memcpy(bytes + used, p, n); used += n; return n;
}
ssize_t __wrap_recv(int fd, void *p, size_t n, int flags) {
    if (fd != 12345) return __real_recv(fd, p, n, flags);
    assert(flags == MSG_DONTWAIT);
    ++calls;
    if (mode == 1 && calls == 1) { errno = EINTR; return -1; }
    if (mode >= 5 && calls == 1) { errno = EAGAIN; return -1; }
    if (mode == 2) return 0;
    if (mode == 3 || mode == 4) { errno = mode == 3 ? EIO : 0; return -1; }
    n = n > 3 ? 3 : n; assert(used + n <= sizeof(bytes));
    memcpy(p, bytes + used, n); used += n; return n;
}
int __wrap_poll(struct pollfd *p, nfds_t n, int timeout) {
    if (n != 1 || p[0].fd != 12345) return __real_poll(p, n, timeout);
    /* The wait gets what remains of the 10 ms transfer deadline. */
    assert(p[0].events == wait_events && timeout > 0 && timeout <= 10);
    ++waits;
    if (mode == 5) return 0;
    if (mode == 6 && waits == 1) { errno = EINTR; return -1; }
    if (mode == 7) { errno = 0; return -1; }
    p[0].revents = p[0].events; return 1;
}
int main(void) {
    struct migration_transport xp; struct migration_transport_fd fdx;
    const char input[] = "partial-stream-transfer";
    char output[sizeof(input)];
    migration_transport_fd_init(&xp, &fdx, 12345, 10);
    for (mode = 0; mode <= 7; ++mode) {
        used = calls = waits = 0; memset(bytes, 0, sizeof(bytes));
        wait_events = POLLOUT;
        int expected = mode == 2 ? EPIPE : mode == 3 ? ENOSPC :
            mode == 4 || mode == 7 ? EIO : mode == 5 ? ETIMEDOUT : 0;
        assert(xp.xp_send(xp.xp_cookie, input, sizeof(input)) == expected);
        assert(calls > 0 && waits == (mode < 5 ? 0 : mode == 6 ? 2 : 1));
        if (!expected) assert(used == sizeof(input) && memcmp(bytes, input, used) == 0);
        used = calls = waits = 0; memcpy(bytes, input, sizeof(input));
        memset(output, 0xa5, sizeof(output));
        wait_events = POLLIN;
        expected = mode == 2 ? ECONNRESET : mode == 3 || mode == 4 || mode == 7 ? EIO :
            mode == 5 ? ETIMEDOUT : 0;
        assert(xp.xp_recv(xp.xp_cookie, output, sizeof(output)) == expected);
        assert(waits == (mode < 5 ? 0 : mode == 6 ? 2 : 1) &&
            (mode == 0 || mode == 1 || mode == 6 ? calls > 1 : calls == 1));
        if (!expected) assert(used == sizeof(input) && memcmp(output, input, used) == 0);
        used = calls = waits = 0;
        assert(xp.xp_send(xp.xp_cookie, NULL, 0) == 0);
        assert(xp.xp_recv(xp.xp_cookie, NULL, 0) == 0);
        assert(calls == 0 && waits == 0);
    }
    int pair[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    migration_transport_fd_init(&xp, &fdx, pair[0], 10);
    assert(xp.xp_send(xp.xp_cookie, input, sizeof(input)) == 0);
    assert(read(pair[1], output, sizeof(output)) == sizeof(output));
    assert(memcmp(output, input, sizeof(input)) == 0);
    assert(xp.xp_recv(xp.xp_cookie, output, 1) == ETIMEDOUT);
    assert(close(pair[1]) == 0);
    assert(xp.xp_recv(xp.xp_cookie, output, 1) == ECONNRESET);
    assert(close(pair[0]) == 0);
    puts("PASS: 8 audited transport fault modes, zero-length I/O, socket timeout and EOF");
}
