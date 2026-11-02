/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CONSUMER_BIRTH_MOCK_H
#define CONSUMER_BIRTH_MOCK_H
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <unistd.h>
/* Models the kernel contract: pdself(2) is capability-mode only (ENOTCAPABLE
 * for an ambient caller); an ambient caller names itself with pdopenpid(2),
 * which capability mode refuses (ECAPMODE).  birth_mock_capmode selects the
 * caller's mode; ambient (0) is the default, as for dtrace(1) from a shell. */
static int birth_mock_error;
static int birth_mock_capmode;
static int birth_mock_capmode_errno;	/* cap_getmode(2) fails with it */
static inline int birth_mock_cap_getmode(u_int *mode) {
    if (birth_mock_capmode_errno != 0) { errno = birth_mock_capmode_errno; return -1; }
    *mode = (u_int)birth_mock_capmode;
    return 0;
}
static inline int birth_mock_pdself(int *fd, int flags) {
    if (flags != (PD_DAEMON | PD_CLOEXEC)) { errno = EINVAL; return -1; }
    if (!birth_mock_capmode) { errno = ENOTCAPABLE; return -1; }
    if (birth_mock_error == 1) { errno = ENOTTY; return -1; }
    *fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    return *fd < 0 ? -1 : 0;
}
static inline int birth_mock_pdopenpid(pid_t pid, int flags) {
    if (flags != (PD_DAEMON | PD_CLOEXEC) || pid != getpid()) { errno = EINVAL; return -1; }
    if (birth_mock_capmode) { errno = ECAPMODE; return -1; }
    if (birth_mock_error == 1) { errno = ENOTTY; return -1; }
    return open("/dev/null", O_RDONLY | O_CLOEXEC);
}
static inline int birth_mock_ioctl(int fd, unsigned long cmd, struct pd_birth_identity *birth) {
    if (fcntl(fd, F_GETFD) < 0 || cmd != PDIOC_GET_BIRTH_IDENTITY) { errno = EINVAL; return -1; }
    if (birth_mock_error == 2) { errno = ESRCH; return -1; }
    *birth = (struct pd_birth_identity){ .pid = getpid(), .start_sec = (uint64_t)getpid(), .start_usec = 123 };
    if (birth_mock_error == 3) birth->pid++;
    if (birth_mock_error == 4) birth->start_usec = 1000000;
    if (birth_mock_error == 5) birth->start_sec = birth->start_usec = 0;
    return 0;
}
#define cap_getmode birth_mock_cap_getmode
#define pdself birth_mock_pdself
#define pdopenpid birth_mock_pdopenpid
#define ioctl birth_mock_ioctl
#endif
