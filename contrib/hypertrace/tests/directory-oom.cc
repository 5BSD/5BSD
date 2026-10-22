/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"

using namespace dtraced;
static int fail_after = -1;
static bool fail_readdir = false;
extern "C" void *__real__Znwm(size_t);
extern "C" struct dirent *__real_readdir(DIR *);
extern "C" struct dirent *__wrap_readdir(DIR *stream)
{
    if (fail_readdir) { fail_readdir = false; errno = EIO; return nullptr; }
    return __real_readdir(stream);
}
extern "C" void *__wrap__Znwm(size_t size)
{
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    return __real__Znwm(size);
}

int main()
{
    char path[] = "/tmp/hypertrace-directory-XXXXXX";
    assert(mkdtemp(path) != nullptr);
    int sv[2], second[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, second) == 0);
    int kq = kqueue(); assert(kq >= 0);
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_ELFWRITE;
    auto *client = new client_fd(kq, sv[0], hello);
    auto *other = new client_fd(kq, second[0], hello);
    assert(client->enable_write(client));
    assert(other->enable_write(other));
    state s{};
    s.sockfds.insert(client);
    s.sockfds.insert(other);
    unsigned failures = 0, successes = 0;
    {
        dir watched(path, &process_outbound);
        watched.state = &s;
        fail_readdir = true;
        assert(!watched.populate_existing() && errno == EIO);
        assert(watched.populate_existing());
        int fd = openat(watched.dirfd, "probe", O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(fd >= 0); assert(close(fd) == 0);
        struct dirent entry{};
        strlcpy(entry.d_name, "probe", sizeof(entry.d_name));
        for (int n = 0; n < 30; ++n) {
            bool ok;
            fail_after = n;
            try { ok = process_outbound(watched, &entry); }
            catch (const std::bad_alloc &) { ok = false; }
            fail_after = -1;
            if (ok) {
                ++successes;
                assert(s.joblist.size() == 2);
            } else {
                ++failures;
                assert(s.joblist.empty());
            }
            for (job *queued : s.joblist) delete queued;
            s.joblist.clear();
            assert(client->is_dead());
            assert(other->is_dead());
            (void)watched.rmpath("probe");
        }
        assert(unlinkat(watched.dirfd, "probe", 0) == 0);
    }
    assert(failures >= 2 && successes >= 1);
    s.sockfds.clear();
    delete client;
    delete other;
    close(sv[1]);
    close(second[1]);
    close(kq);
    assert(rmdir(path) == 0);
    puts("PASS: directory read errors and multi-client notification allocation failures preserve atomic queue ownership");
}
