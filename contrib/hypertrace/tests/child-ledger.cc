/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include "dtraced_child_ledger.h"

static pid_t requested_pid = -1;
static int returned_procfd = -1;
static int busy_retries;

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int __wrap_ioctl(int fd, unsigned long command, ...)
{
    va_list args;
    va_start(args, command);
    void *data = va_arg(args, void *);
    va_end(args);
    if (command != PDIOC_GET_BIRTH_IDENTITY)
        return __real_ioctl(fd, command, data);
    pid_t pid;
    if (pdgetpid(fd, &pid) != 0) return -1;
    auto *birth = static_cast<pd_birth_identity *>(data);
    *birth = {pid, 0, 987, static_cast<uint64_t>(pid % 1000000)};
    return 0;
}

extern "C" int __wrap_pdopenpid(pid_t pid, int flags)
{
    assert(flags == (PD_DAEMON | PD_CLOEXEC));
    if (busy_retries-- > 0) { errno = EBUSY; return -1; }
    if (pid != requested_pid || returned_procfd < 0) {
        errno = ESRCH;
        return -1;
    }
    return dup(returned_procfd);
}

static pid_t
spawn(int &fd)
{
    pid_t pid = pdfork(&fd, PD_CLOEXEC);
    assert(pid >= 0);
    if (pid == 0) {
        for (;;) pause();
    }
    return pid;
}

static void
wait_dead(int fd)
{
    struct pollfd ready{fd, POLLHUP, 0};
    assert(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLHUP));
    int status;
    int result = pdwait(fd, &status, WEXITED, nullptr, nullptr);
    assert(result == 0 || (result == -1 && errno == ESRCH));
    if (result == 0)
        assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
}

int
main()
{
    char path[] = "/tmp/hypertrace-child-ledger.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(directory >= 0);
    assert(!dtraced::recover_guest_children(directory, true) && errno == EBUSY);
    assert(dtraced::recover_guest_children(directory, false));

    int first_fd;
    pid_t first = spawn(first_fd);
    assert(dtraced::record_guest_child(directory, first_fd, first));
    requested_pid = first;
    returned_procfd = first_fd;
    busy_retries = 1;
    assert(dtraced::recover_guest_children(directory, true));
    assert(busy_retries < 0);
    wait_dead(first_fd);
    close(first_fd);

    int old_fd;
    pid_t old_pid = spawn(old_fd);
    assert(dtraced::record_guest_child(directory, old_fd, old_pid));
    assert(pdkill(old_fd, SIGKILL) == 0);
    wait_dead(old_fd);
    close(old_fd);
    int new_fd;
    pid_t new_pid = spawn(new_fd);
    requested_pid = old_pid;
    returned_procfd = new_fd; /* Reopened PID has a different birth. */
    assert(dtraced::recover_guest_children(directory, true));
    assert(kill(new_pid, 0) == 0);
    assert(pdkill(new_fd, SIGKILL) == 0);
    wait_dead(new_fd);
    close(new_fd);

    int corrupt = openat(directory, ".child.123456",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(corrupt >= 0);
    assert(write(corrupt, "x", 1) == 1 && close(corrupt) == 0);
    assert(!dtraced::recover_guest_children(directory, true) &&
        errno == EPROTO);
    assert(unlinkat(directory, ".child.123456", 0) == 0);

    DIR *scan = opendir(path);
    assert(scan != nullptr);
    while (dirent *entry = readdir(scan)) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            assert(unlinkat(directory, entry->d_name, 0) == 0);
    }
    assert(closedir(scan) == 0);
    close(directory);
    assert(rmdir(path) == 0);
    puts("PASS: durable child ledger rejects unmarked/corrupt cleanup, waits exact child exit, ignores reused PID");
}
