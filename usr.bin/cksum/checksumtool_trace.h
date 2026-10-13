/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CHECKSUMTOOL_TRACE_H_
#define _CHECKSUMTOOL_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <checksumtool_provider.h>
#define TRACE_CHECKSUMTOOL_FILE__START(a0) do { \
	if (CHECKSUMTOOL_FILE_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		CHECKSUMTOOL_FILE_START((int)(a0)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CHECKSUMTOOL_FILE__DONE(a0, a1, a2, a3) do { \
	if (CHECKSUMTOOL_FILE_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CHECKSUMTOOL_FILE_DONE((int)(a0), (int64_t)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_CHECKSUMTOOL_FILE__START(a0) do { } while (0)
#define TRACE_CHECKSUMTOOL_FILE__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
