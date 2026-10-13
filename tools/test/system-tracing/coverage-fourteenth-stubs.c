/* SPDX-License-Identifier: BSD-2-Clause */
/* Test-only link wrappers: never change the real kernel environment or root. */
#include <sys/types.h>
#include <errno.h>
#include <kenv.h>
#include <stdlib.h>
#include <string.h>

int
__wrap_chroot(const char *path)
{
	(void)path;
	if (getenv("DTRACE_TEST_FAIL") != NULL) {
		errno = EPERM;
		return (-1);
	}
	return (0);
}

int
__wrap_kenv(int action, const char *name, char *value, int length)
{
	static const char dump[] = "trace_fixture=value\0";

	(void)name;
	if (getenv("DTRACE_TEST_FAIL") != NULL) {
		errno = ENOENT;
		return (-1);
	}
	switch (action) {
	case KENV_GET:
		if (length < 6) {
			errno = ERANGE;
			return (-1);
		}
		memcpy(value, "value", 6);
		return (6);
	case KENV_SET:
	case KENV_UNSET:
		return (0);
	default:
		if (value == NULL)
			return (sizeof(dump));
		if (length < (int)sizeof(dump))
			return (sizeof(dump));
		memcpy(value, dump, sizeof(dump));
		return (0);
	}
}
