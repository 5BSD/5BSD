/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CATIO_TRACE_H_
#define _CATIO_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <catio_provider.h>
#define TRACE_CATIO_READ__START(a0, a1) do { \
	if (CATIO_READ_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		CATIO_READ_START((int)(a0), (size_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CATIO_READ__DONE(a0, a1, a2, a3) do { \
	if (CATIO_READ_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CATIO_READ_DONE((int)(a0), (size_t)(a1), (int64_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CATIO_WRITE__START(a0, a1) do { \
	if (CATIO_WRITE_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		CATIO_WRITE_START((int)(a0), (size_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_CATIO_WRITE__DONE(a0, a1, a2, a3) do { \
	if (CATIO_WRITE_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		CATIO_WRITE_DONE((int)(a0), (size_t)(a1), (int64_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_CATIO_READ__START(a0, a1) do { } while (0)
#define TRACE_CATIO_READ__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_CATIO_WRITE__START(a0, a1) do { } while (0)
#define TRACE_CATIO_WRITE__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
