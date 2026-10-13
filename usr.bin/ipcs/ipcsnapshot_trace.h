/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _IPCSNAPSHOT_TRACE_H_
#define _IPCSNAPSHOT_TRACE_H_
#ifdef WITH_COVERAGE_DTRACE
#include <errno.h>
#include <ipcsnapshot_provider.h>
#define TRACE_QUERY__START(a0, a1) do { \
	if (IPCSNAPSHOT_QUERY_START_ENABLED()) { \
		int saved_trace_errno = errno; \
		IPCSNAPSHOT_QUERY_START((int)(a0), (size_t)(a1)); \
		errno = saved_trace_errno; \
	} \
} while (0)
#define TRACE_QUERY__DONE(a0, a1, a2) do { \
	if (IPCSNAPSHOT_QUERY_DONE_ENABLED()) { \
		int saved_trace_errno = errno; \
		IPCSNAPSHOT_QUERY_DONE((int)(a0), (int)(a1), (size_t)(a2)); \
		errno = saved_trace_errno; \
	} \
} while (0)
static int
trace_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen)
{
	int result, error;

	TRACE_QUERY__START(oldp == NULL, oldp != NULL && oldlenp != NULL ? *oldlenp : 0);
	result = sysctlbyname(name, oldp, oldlenp, newp, newlen);
	error = errno;
	TRACE_QUERY__DONE(result, result == -1 ? error : 0,
	    result == 0 && oldlenp != NULL ? *oldlenp : 0);
	errno = error;
	return (result);
}

#else
#define TRACE_QUERY__START(a0, a1) do { } while (0)
#define TRACE_QUERY__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
