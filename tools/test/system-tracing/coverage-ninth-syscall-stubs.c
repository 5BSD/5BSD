/* SPDX-License-Identifier: BSD-2-Clause */
/* Link-only test replacements. Never call the actual module/sync syscalls. */
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
static int
outcome(const char *operation, int success)
{
 const char *value;
 int error;
 value = getenv("DTRACE_TEST_ERRNO");
 error = value == NULL ? 0 : atoi(value);
 printf("intercepted %s\n", operation);
 errno = error;
 return (error == 0 ? success : -1);
}
int __wrap_kldload(const char *path) { (void)path; return (outcome("load", 4321)); }
int __wrap_kldunloadf(int id, int flags) { (void)id; (void)flags; return (outcome("unload", 0)); }
void __wrap_sync(void) { (void)outcome("sync", 0); }
int __wrap_chflagsat(int fd, const char *path, unsigned long flags, int atflags)
{
 (void)fd; (void)path; (void)flags; (void)atflags;
 return (outcome("flags", 0));
}
