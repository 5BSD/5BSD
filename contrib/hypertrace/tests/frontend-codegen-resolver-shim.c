/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded by frontend-codegen-unit's resolver checks: gethostname() and
 * sysctlbyname("kern.osrelease") fail with EIO, as if the local identity
 * could not be read.
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>

int
gethostname(char *name, size_t len)
{
	(void) name; (void) len;
	errno = EIO;
	return (-1);
}

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	static int (*real)(const char *, void *, size_t *, const void *,
	    size_t);

	if (strcmp(name, "kern.osrelease") == 0) {
		errno = EIO;
		return (-1);
	}
	if (real == NULL)
		real = (int (*)(const char *, void *, size_t *, const void *,
		    size_t))dlsym(RTLD_NEXT, "sysctlbyname");
	return (real(name, oldp, oldlenp, newp, newlen));
}
