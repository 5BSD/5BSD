/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _TEEIO_TRACE_H_
#define _TEEIO_TRACE_H_
#include <errno.h>
#include <stdint.h>
#ifdef WITH_COVERAGE_DTRACE
#include <teeio_provider.h>
#define TRACE_TEEIO_READ__START(a0, a1) do { \
	if (TEEIO_READ_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		TEEIO_READ_START((int)(a0), (size_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TEEIO_READ__DONE(a0, a1, a2, a3) do { \
	if (TEEIO_READ_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		TEEIO_READ_DONE((int)(a0), (size_t)(a1), (int64_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TEEIO_WRITE__START(a0, a1) do { \
	if (TEEIO_WRITE_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		TEEIO_WRITE_START((int)(a0), (size_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_TEEIO_WRITE__DONE(a0, a1, a2, a3) do { \
	if (TEEIO_WRITE_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		TEEIO_WRITE_DONE((int)(a0), (size_t)(a1), (int64_t)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_TEEIO_READ__START(a0, a1) do { } while (0)
#define TRACE_TEEIO_READ__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_TEEIO_WRITE__START(a0, a1) do { } while (0)
#define TRACE_TEEIO_WRITE__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
