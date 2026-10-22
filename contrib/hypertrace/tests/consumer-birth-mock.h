/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CONSUMER_BIRTH_MOCK_H
#define CONSUMER_BIRTH_MOCK_H
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <unistd.h>
static int birth_mock_error;
static inline int birth_mock_pdself(int *fd, int flags) {
    if (flags != (PD_DAEMON | PD_CLOEXEC)) { errno = EINVAL; return -1; }
    if (birth_mock_error == 1) { errno = ENOTTY; return -1; }
    *fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    return *fd < 0 ? -1 : 0;
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
#define pdself birth_mock_pdself
#define ioctl birth_mock_ioctl
#endif
