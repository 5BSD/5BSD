/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * A host libc may predate pdopenpid(2); source builds use new libc.  This
 * object's definition takes precedence over libc's, so forward to the system
 * call: the suites then pin real process descriptors as the daemon does.
 */
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
extern "C" __attribute__((weak)) int
pdopenpid(pid_t pid, int flags)
{
    return (syscall(SYS_pdopenpid, pid, flags));
}
