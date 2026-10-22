/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACE_IDENTIFIERS_H
#define DTRACE_IDENTIFIERS_H
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dtraced.h"
#include "dtraced_io.h"
#include "dtraced_wire.h"

/* stdin may be a pipe or a socket. One reader owns the whole handshake. */
static inline int
dtrace_ident_read_exact(int fd, void *data, size_t length, int64_t deadline)
{
    unsigned char *out = (unsigned char *)data;
    while (length != 0) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int timeout;
        if (dtraced_io_remaining_timeout(deadline, &timeout) != 0)
            return (-1);
        int result = poll(&pfd, 1, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return (-1);
        if (result == 0) continue;
        if (pfd.revents & POLLNVAL) { errno = EBADF; return (-1); }
        ssize_t n = read(fd, out, length);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n <= 0) { if (n == 0) errno = EPIPE; return (-1); }
        out += n; length -= (size_t)n;
    }
    return (0);
}

static inline int
dtrace_read_identifiers(int fd, unsigned char **identifiers, size_t *count,
    size_t identifier_size, int64_t deadline)
{
    size_t n;
    *identifiers = NULL; *count = 0;
    if (identifier_size == 0) { errno = EINVAL; return (-1); }
    unsigned char count_wire[8];
    uint64_t decoded;
    if (dtrace_ident_read_exact(fd, count_wire, sizeof(count_wire),
        deadline) != 0)
        return (-1);
    decoded = dtraced_wire_get_u64(count_wire);
    if (decoded > SIZE_MAX) { errno = EOVERFLOW; return (-1); }
    n = (size_t)decoded;
    if (n == 0 || n > (64U * 1024U * 1024U) / identifier_size) {
        errno = EINVAL; return (-1);
    }
    unsigned char *data = (unsigned char *)malloc(n * identifier_size);
    if (data == NULL) return (-1);
    if (dtrace_ident_read_exact(fd, data, n * identifier_size, deadline) != 0) {
        int error = errno; free(data); errno = error; return (-1);
    }
    *identifiers = data; *count = n;
    return (0);
}

static inline int
dtrace_write_launch_result(int fd, int installed, const char *source_ident,
    size_t ident_length, int64_t deadline)
{
    dtraced_launch_result_t result = { 0 };
    unsigned char wire[DTRACED_LAUNCH_WIRE_SIZE];
    size_t transferred;

    if ((installed != 0 && installed != 1) || source_ident == NULL ||
        ident_length != sizeof(result.source_ident)) {
        errno = EINVAL;
        return (-1);
    }
    result.magic = DTRACED_LAUNCH_MAGIC;
    result.installed = installed;
    memcpy(result.source_ident, source_ident, ident_length);
    dtraced_wire_encode_launch(wire, &result);
    return (dtraced_io_transfer(fd, wire, sizeof(wire), true,
        deadline, &transferred));
}
#endif
