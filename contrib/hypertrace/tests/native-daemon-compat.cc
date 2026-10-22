/* SPDX-License-Identifier: BSD-2-Clause */
/* The running host libc predates pdopenpid(2); source builds use new libc. */
#include <sys/types.h>
#include <cerrno>
extern "C" __attribute__((weak)) int
pdopenpid(pid_t, int)
{
    errno = ENOSYS;
    return -1;
}
