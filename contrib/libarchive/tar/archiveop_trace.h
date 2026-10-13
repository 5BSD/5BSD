/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _ARCHIVEOP_TRACE_H_
#define _ARCHIVEOP_TRACE_H_
#ifdef WITH_COVERAGE_DTRACE
#include <errno.h>
#include <archiveop_provider.h>
#define TRACE_OPERATION__START(a0) do { \
	if (ARCHIVEOP_OPERATION_START_ENABLED()) { \
		int saved_trace_errno = errno; \
		ARCHIVEOP_OPERATION_START((int)(a0)); \
		errno = saved_trace_errno; \
	} \
} while (0)
#define TRACE_OPERATION__DONE(a0, a1) do { \
	if (ARCHIVEOP_OPERATION_DONE_ENABLED()) { \
		int saved_trace_errno = errno; \
		ARCHIVEOP_OPERATION_DONE((int)(a0), (int)(a1)); \
		errno = saved_trace_errno; \
	} \
} while (0)
static int
trace_archive_read_next_header(struct archive *a, struct archive_entry **entry)
{
	int result, error;

	TRACE_OPERATION__START(1);
	result = archive_read_next_header(a, entry);
	error = errno;
	TRACE_OPERATION__DONE(1, result);
	errno = error;
	return (result);
}
static int
trace_archive_read_extract2(struct archive *a, struct archive_entry *entry, struct archive *writer)
{
	int result, error;

	TRACE_OPERATION__START(2);
	result = archive_read_extract2(a, entry, writer);
	error = errno;
	TRACE_OPERATION__DONE(2, result);
	errno = error;
	return (result);
}

#else
#define TRACE_OPERATION__START(a0) do { } while (0)
#define TRACE_OPERATION__DONE(a0, a1) do { } while (0)
#endif
#endif
