/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Preloaded interposer for frontend-parser-corpus.py: models the kernel's
 * debug.dtrace.providers sysctl (a space-separated provider list) so that
 * "#pragma D depends_on provider" can be tested offline.  Every other
 * sysctl is passed to libc.
 */
#include <sys/types.h>
#include <sys/sysctl.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp,
    size_t newlen)
{
	static int (*real)(const char *, void *, size_t *, const void *,
	    size_t);
	const char *list = getenv("FRONTEND_PROVIDERS");

	if (list != NULL && strcmp(name, "debug.dtrace.providers") == 0) {
		size_t n = strlen(list) + 1;

		if (oldp == NULL) {
			*oldlenp = n;
			return (0);
		}
		if (*oldlenp < n) {
			errno = ENOMEM;
			return (-1);
		}
		memcpy(oldp, list, n);
		*oldlenp = n;
		return (0);
	}
	if (real == NULL)
		real = (int (*)(const char *, void *, size_t *, const void *,
		    size_t))dlsym(RTLD_NEXT, "sysctlbyname");
	return (real(name, oldp, oldlenp, newp, newlen));
}
