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
static size_t used;
static unsigned char bytes[64];
ssize_t __real_read(int, void *, size_t);
ssize_t __real_write(int, const void *, size_t);
int __real_poll(struct pollfd *, nfds_t, int);
ssize_t __wrap_write(int fd, const void *p, size_t n) {
    if (fd != 12345) return __real_write(fd, p, n);
    ++calls;
    if (mode == 1 && calls == 1) { errno = EINTR; return -1; }
    if (mode == 2) return 0;
    if (mode == 3 || mode == 4) { errno = mode == 3 ? ENOSPC : 0; return -1; }
    n = n > 3 ? 3 : n; assert(used + n <= sizeof(bytes));
    memcpy(bytes + used, p, n); used += n; return n;
}
ssize_t __wrap_read(int fd, void *p, size_t n) {
    if (fd != 12345) return __real_read(fd, p, n);
    ++calls;
    if (mode == 1 && calls == 1) { errno = EINTR; return -1; }
    if (mode == 2) return 0;
    if (mode == 3 || mode == 4) { errno = mode == 3 ? EIO : 0; return -1; }
    n = n > 3 ? 3 : n; assert(used + n <= sizeof(bytes));
    memcpy(p, bytes + used, n); used += n; return n;
}
int __wrap_poll(struct pollfd *p, nfds_t n, int timeout) {
    if (n != 1 || p[0].fd != 12345) return __real_poll(p, n, timeout);
    assert(p[0].events == POLLIN && timeout == 10); ++waits;
    if (mode == 5) return 0;
    if (mode == 6 || mode == 7) { errno = mode == 6 ? EINTR : 0; return -1; }
    p[0].revents = POLLIN; return 1;
}
int main(void) {
    struct migration_transport xp; struct migration_transport_fd fdx;
    const char input[] = "partial-stream-transfer";
    char output[sizeof(input)];
    migration_transport_fd_init(&xp, &fdx, 12345, 10);
    for (mode = 0; mode <= 7; ++mode) {
        used = calls = waits = 0; memset(bytes, 0, sizeof(bytes));
        int expected = mode == 2 ? EPIPE : mode == 3 ? ENOSPC : mode == 4 ? EIO : 0;
        assert(xp.xp_send(xp.xp_cookie, input, sizeof(input)) == expected);
        assert(calls > 0 && waits == 0);
        if (!expected) assert(used == sizeof(input) && memcmp(bytes, input, used) == 0);
        used = calls = waits = 0; memcpy(bytes, input, sizeof(input));
        memset(output, 0xa5, sizeof(output));
        expected = mode == 2 ? ECONNRESET : mode == 3 || mode == 4 || mode == 7 ? EIO :
            mode == 5 ? ETIMEDOUT : mode == 6 ? EINTR : 0;
        assert(xp.xp_recv(xp.xp_cookie, output, sizeof(output)) == expected);
        assert(waits > 0 && (mode >= 5 ? calls == 0 : calls > 0));
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
