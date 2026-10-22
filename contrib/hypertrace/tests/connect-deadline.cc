/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/un.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include "dtraced_io.h"

static int mode;
static int connect_calls;
extern "C" int __real_connect(int, const struct sockaddr *, socklen_t);
extern "C" int __wrap_connect(int fd, const struct sockaddr *address,
    socklen_t length)
{
    ++connect_calls;
    if (mode == 5) return 0;
    if (mode == 1) { errno = EINPROGRESS; return -1; }
    if (mode == 2) { errno = EACCES; return -1; }
    if (mode == 3) { errno = EINPROGRESS; return -1; }
    if (mode == 4) { errno = EINPROGRESS; return -1; }
    return __real_connect(fd, address, length);
}
extern "C" int __real_getsockopt(int, int, int, void *, socklen_t *);
extern "C" int __wrap_getsockopt(int fd, int level, int option, void *value,
    socklen_t *length)
{
    if (mode == 4) {
        assert(level == SOL_SOCKET && option == SO_ERROR);
        assert(*length >= sizeof(int));
        *static_cast<int *>(value) = ECONNREFUSED;
        *length = sizeof(int);
        return 0;
    }
    return __real_getsockopt(fd, level, option, value, length);
}
extern "C" int __real_poll(struct pollfd *, nfds_t, int);
extern "C" int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    if (mode == 3) { usleep(1000); return 0; }
    return __real_poll(fds, count, timeout);
}

int main()
{
    char directory[] = "/tmp/hypertrace-connect-XXXXXX";
    assert(mkdtemp(directory) != nullptr);
    sockaddr_un local{};
    local.sun_family = AF_UNIX;
    assert(snprintf(local.sun_path, sizeof(local.sun_path), "%s/socket",
        directory) < (int)sizeof(local.sun_path));
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener >= 0);
    assert(bind(listener, reinterpret_cast<sockaddr *>(&local),
        sizeof(local)) == 0);
    assert(listen(listener, 1) == 0);
    int client = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    assert(client >= 0);
    mode = 0;
    int64_t now = dtraced_io_milliseconds();
    assert(dtraced_io_connect(client, reinterpret_cast<sockaddr *>(&local),
        sizeof(local), now + 1000) == 0);
    int peer = accept(listener, nullptr, nullptr);
    assert(peer >= 0);
    close(peer); close(client); close(listener);
    assert(unlink(local.sun_path) == 0 && rmdir(directory) == 0);

    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    sockaddr address{};
    now = dtraced_io_milliseconds();
    mode = 1;
    assert(dtraced_io_connect(sv[0], &address, sizeof(address), now + 100) == 0);
    mode = 2;
    assert(dtraced_io_connect(sv[0], &address, sizeof(address), now + 100) == -1);
    assert(errno == EACCES);
    mode = 4;
    assert(dtraced_io_connect(sv[0], &address, sizeof(address), now + 100) == -1);
    assert(errno == ECONNREFUSED);
    mode = 3;
    now = dtraced_io_milliseconds();
    assert(dtraced_io_connect(sv[0], &address, sizeof(address), now + 20) == -1);
    assert(errno == ETIMEDOUT);
    mode = 5;
    connect_calls = 0;
    now = dtraced_io_milliseconds();
    assert(dtraced_io_connect(sv[0], &address, sizeof(address), now) == -1);
    assert(errno == ETIMEDOUT && connect_calls == 0);
    close(sv[0]); close(sv[1]);
    puts("PASS: nonblocking connect completion, refusal, and absolute timeout");
}
