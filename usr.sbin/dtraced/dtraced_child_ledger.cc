/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <unistd.h>
#include <vector>
#include "dtraced_child_ledger.h"

namespace dtraced {
namespace {
constexpr uint64_t child_magic = UINT64_C(0x31444c4948435444); /* DTCHILD1 */
constexpr const char *marker = ".child-ledger-v1";
struct child_record {
    uint64_t magic;
    uint8_t boot_id[16];
    pd_birth_identity birth;
};
static_assert(sizeof(child_record) == 48, "fixed child record");

bool
child_name(pid_t pid, char name[32])
{
    if (pid <= 1) { errno = EINVAL; return false; }
    int n = snprintf(name, 32, ".child.%d", pid);
    if (n < 0 || n >= 32) { errno = EOVERFLOW; return false; }
    return true;
}

bool
boot_identity(uint8_t id[16])
{
    size_t length = 16;
    if (sysctlbyname("kern.boot_id", id, &length, nullptr, 0) != 0)
        return false;
    if (length != 16) { errno = EPROTO; return false; }
    return true;
}

bool
sync_directory(int directory)
{
    return fsync(directory) == 0;
}

bool
write_exact(int fd, const void *data, size_t size)
{
    const auto *bytes = static_cast<const uint8_t *>(data);
    while (size != 0) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (n == 0) errno = EIO; return false; }
        bytes += n;
        size -= size_t(n);
    }
    return true;
}

bool
read_exact_record(int directory, const char *name, child_record &record)
{
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st{};
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size == sizeof(record) && st.st_nlink == 1;
    if (!ok) errno = EPROTO;
    if (ok) {
        uint8_t *bytes = reinterpret_cast<uint8_t *>(&record);
        size_t remaining = sizeof(record);
        while (remaining != 0) {
            ssize_t n = read(fd, bytes, remaining);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { if (n == 0) errno = EPROTO; ok = false; break; }
            bytes += n;
            remaining -= size_t(n);
        }
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return ok;
}

bool
identity_equal(const pd_birth_identity &a, const pd_birth_identity &b)
{
    return a.pid == b.pid && a.reserved == 0 && b.reserved == 0 &&
        a.start_sec == b.start_sec && a.start_usec == b.start_usec;
}

bool
wait_child_exit(int fd)
{
    struct pollfd ready{fd, POLLHUP, 0};
    int result;
    do { result = poll(&ready, 1, 10000); }
    while (result < 0 && errno == EINTR);
    if (result <= 0 || (ready.revents & POLLHUP) == 0) {
        errno = result == 0 ? ETIMEDOUT : (result > 0 ? EIO : errno);
        return false;
    }
    int status;
    return pdwait(fd, &status, WEXITED, nullptr, nullptr) == 0 ||
        errno == ESRCH;
}

bool
resolve_child(int directory, const char *name, pid_t pid,
    const uint8_t boot_id[16])
{
    child_record record{};
    if (!read_exact_record(directory, name, record)) return false;
    if (record.magic != child_magic || record.birth.pid != pid ||
        record.birth.reserved != 0 || record.birth.start_usec >= 1000000) {
        errno = EPROTO;
        return false;
    }
    if (memcmp(record.boot_id, boot_id, 16) == 0) {
        int fd = -1;
        /* pdopenpid refuses P_WEXIT while the old child is finishing its
         * exit. It may disappear or its PID may be reused during this wait;
         * either outcome is resolved only after a fresh descriptor query. */
        for (unsigned attempt = 0; attempt < 1000; ++attempt) {
            fd = pdopenpid(pid, PD_DAEMON | PD_CLOEXEC);
            if (fd >= 0 || errno != EBUSY) break;
            if (attempt == 999) break;
            (void)usleep(10000);
        }
        if (fd < 0 && errno != ESRCH) return false;
        if (fd >= 0) {
            pd_birth_identity current{};
            if (ioctl(fd, PDIOC_GET_BIRTH_IDENTITY, &current) != 0) {
                int error = errno;
                if (error == ESRCH && !wait_child_exit(fd))
                    error = errno;
                close(fd);
                if (error != ESRCH) { errno = error; return false; }
            } else {
                if (identity_equal(record.birth, current)) {
                    if (pdkill(fd, SIGKILL) != 0 && errno != ESRCH) {
                        int error = errno; close(fd); errno = error;
                        return false;
                    }
                    if (!wait_child_exit(fd)) {
                        int error = errno; close(fd); errno = error;
                        return false;
                    }
                }
                close(fd);
            }
        }
    }
    if (unlinkat(directory, name, 0) != 0) return false;
    return sync_directory(directory);
}
}

bool
record_guest_child(int directory, int procfd, pid_t pid)
{
    char name[32];
    if (!child_name(pid, name)) return false;
    child_record record{};
    record.magic = child_magic;
    if (!boot_identity(record.boot_id) ||
        ioctl(procfd, PDIOC_GET_BIRTH_IDENTITY, &record.birth) != 0)
        return false;
    if (record.birth.pid != pid || record.birth.reserved != 0 ||
        record.birth.start_usec >= 1000000) {
        errno = EPROTO; return false;
    }
    int fd = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = write_exact(fd, &record, sizeof(record)) && fsync(fd) == 0;
    int error = errno;
    if (close(fd) != 0 && ok) { ok = false; error = errno; }
    if (ok) { ok = sync_directory(directory); error = errno; }
    if (!ok) {
        (void)unlinkat(directory, name, 0);
        (void)sync_directory(directory);
        errno = error;
    }
    return ok;
}

bool
retire_guest_child(int directory, pid_t pid)
{
    char name[32];
    if (!child_name(pid, name)) return false;
    if (unlinkat(directory, name, 0) != 0 && errno != ENOENT)
        return false;
    return sync_directory(directory);
}

bool
recover_guest_children(int directory, bool pending_cleanup)
{
    int fd = openat(directory, marker, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno != ENOENT) return false;
    if (pending_cleanup && fd < 0) { errno = EBUSY; return false; }
    if (fd >= 0) {
        struct stat st{};
        bool valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_size == 0 && st.st_nlink == 1;
        int error = valid ? 0 : EPROTO;
        close(fd);
        if (!valid) { errno = error; return false; }
    }
    uint8_t boot_id[16];
    if (!boot_identity(boot_id)) return false;
    int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scanfd < 0) return false;
    DIR *scan = fdopendir(scanfd);
    if (scan == nullptr) { int error = errno; close(scanfd); errno = error; return false; }
    bool ok = true;
    std::vector<std::string> names;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(scan)) != nullptr) {
        if (strncmp(entry->d_name, ".child.", 7) != 0) continue;
        unsigned long value = 0;
        const char *p = entry->d_name + 7;
        if (*p < '1' || *p > '9') { errno = EPROTO; ok = false; break; }
        for (; *p != '\0'; ++p) {
            if (*p < '0' || *p > '9' ||
                value > (INT32_MAX - unsigned(*p - '0')) / 10) {
                errno = EPROTO; ok = false; break;
            }
            value = value * 10 + unsigned(*p - '0');
        }
        if (!ok) break;
        if (value <= 1) { errno = EPROTO; ok = false; break; }
        names.emplace_back(entry->d_name);
        errno = 0;
    }
    int error = errno;
    closedir(scan);
    if (!ok || error != 0) { errno = error; return false; }
    for (const auto &name : names) {
        unsigned long value = strtoul(name.c_str() + 7, nullptr, 10);
        if (!resolve_child(directory, name.c_str(), pid_t(value), boot_id))
            return false;
    }
    if (fd < 0) {
        fd = openat(directory, marker,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) return false;
        bool synced = fsync(fd) == 0;
        error = errno;
        if (close(fd) != 0 && synced) { synced = false; error = errno; }
        if (synced) { synced = sync_directory(directory); error = errno; }
        if (!synced) { errno = error; return false; }
    }
    return true;
}
}
