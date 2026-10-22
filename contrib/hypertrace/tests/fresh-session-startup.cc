/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <dttransport.h>
#include "dtraced_directory.h"
#include "dtraced_state.h"
using namespace dtraced;
static int transport = -1, ready_reports, bind_calls;
static dtt_vm_identity identity{7, 6, DTT_IDENTITY_FRESH_PENDING, 11, 10};
static const char child[] = ".session.0007.000000000000000b";
extern "C" int __real_open(const char *, int, ...);
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" int __real_remove(const char *);
extern "C" int __wrap_open(const char *path, int flags, ...) {
    if (strcmp(path, "/dev/dttransport") == 0)
        return transport = __real_open("/dev/null", flags);
    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? va_arg(args, int) : 0;
    va_end(args);
    return __real_open(path, flags, mode);
}
extern "C" int __wrap_remove(const char *path) {
    if (strcmp(path, DTRACED_SOCKPATH) == 0) { errno = ENOENT; return -1; }
    return __real_remove(path);
}
extern "C" int __wrap_ioctl(int fd, unsigned long command, ...) {
    assert(fd == transport);
    va_list args; va_start(args, command); void *data = va_arg(args, void *); va_end(args);
    if (command == DTT_GET_VM_IDENTITY) {
        *static_cast<dtt_vm_identity *>(data) = identity;
        return 0;
    }
    assert(command == DTT_GET_CLEANUP_STATE);
    *static_cast<dtt_cleanup_state *>(data) = {123, 10, 6,
        DTT_CLEANUP_STATE_PENDING | DTT_CLEANUP_STATE_APPLIED |
        DTT_CLEANUP_STATE_SESSION_STOP, 0};
    return 0;
}
extern "C" ssize_t __wrap_write(int fd, const void *data, size_t size) {
    if (fd != transport) return __real_write(fd, data, size);
    assert(size == sizeof(dtt_entry_t));
    const auto &entry = *static_cast<const dtt_entry_t *>(data);
    assert(entry.event_kind == DTT_SESSION_READY && entry.u.cleanup.vmid == 7 &&
        entry.u.cleanup.epoch == 11 && entry.u.cleanup.delivery_id == 123);
    for (const char *root : {INBOUNDDIR, OUTBOUNDDIR, BASEDIR}) {
        char path[MAXPATHLEN]; struct stat st;
        snprintf(path, sizeof(path), "%s/%s", root, child);
        assert(lstat(path, &st) == 0 && S_ISDIR(st.st_mode));
    }
    ready_reports++;
    identity.flags = DTT_IDENTITY_FRESH_ACTIVE;
    return size;
}
extern "C" int __wrap_bind(int, const struct sockaddr *, socklen_t) {
    assert(identity.flags == DTT_IDENTITY_FRESH_ACTIVE && ready_reports == 1);
    bind_calls++;
    errno = EACCES; /* Stop before worker creation; never bind a real daemon socket. */
    return -1;
}
int main() {
    char root[] = "/tmp/hypertrace-fresh-startup.XXXXXX";
    assert(mkdtemp(root));
    const char *argv[] = {"test-dtraced", nullptr};
    char *paths[] = {INBOUNDDIR, OUTBOUNDDIR, BASEDIR};
    for (unsigned i = 0; i < 3; i++) {
        snprintf(paths[i], MAXPATHLEN, "%s/%u", root, i);
        assert(mkdir(paths[i], 0700) == 0);
        int parent = open(paths[i], O_RDONLY | O_DIRECTORY);
        int fd = openat(parent, "old-journal", O_CREAT | O_EXCL | O_WRONLY, 0600);
        assert(fd >= 0 && close(fd) == 0 && close(parent) == 0);
    }
    { state s{}; assert(!s.initialize(0, 0, 1, argv, nullptr, nullptr)); }
    assert(ready_reports == 1 && bind_calls == 1);
    { state s{}; assert(!s.initialize(0, 0, 1, argv, nullptr, nullptr)); }
    assert(ready_reports == 1 && bind_calls == 2);
    int base = open(BASEDIR, O_RDONLY | O_DIRECTORY);
    assert(unlinkat(base, child, AT_REMOVEDIR) == 0 && close(base) == 0);
    { state s{}; assert(!s.initialize(0, 0, 1, argv, nullptr, nullptr)); }
    assert(ready_reports == 1 && bind_calls == 2);
    for (unsigned i = 0; i < 3; i++) {
        int parent = open(paths[i], O_RDONLY | O_DIRECTORY);
        assert(faccessat(parent, "old-journal", F_OK, 0) == 0);
        if (i != 2) assert(unlinkat(parent, child, AT_REMOVEDIR) == 0);
        assert(unlinkat(parent, "old-journal", 0) == 0 && close(parent) == 0);
        assert(rmdir(paths[i]) == 0);
    }
    assert(rmdir(root) == 0);
}
