/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DDIO_TRACE_H_
#define _DDIO_TRACE_H_

#include <errno.h>
#include <stdint.h>

#ifdef WITH_COVERAGE_DTRACE
#include <ddio_provider.h>

#define TRACE_DDIO_READ__START(a0, a1) do { \
	if (DDIO_READ_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_READ_START((int)(a0), (uint64_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_READ__DONE(a0, a1, a2) do { \
	if (DDIO_READ_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_READ_DONE((int)(a0), (int64_t)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_WRITE__START(a0, a1) do { \
	if (DDIO_WRITE_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_WRITE_START((int)(a0), (uint64_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_WRITE__DONE(a0, a1, a2) do { \
	if (DDIO_WRITE_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_WRITE_DONE((int)(a0), (int64_t)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_SPARSE(a0, a1) do { \
	if (DDIO_SPARSE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_SPARSE((int)(a0), (uint64_t)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_SYNC__START(a0, a1) do { \
	if (DDIO_SYNC_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_SYNC_START((int)(a0), (int)(a1)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_DDIO_SYNC__DONE(a0, a1, a2, a3) do { \
	if (DDIO_SYNC_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		DDIO_SYNC_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_DDIO_READ__START(a0, a1) do { } while (0)
#define TRACE_DDIO_READ__DONE(a0, a1, a2) do { } while (0)
#define TRACE_DDIO_WRITE__START(a0, a1) do { } while (0)
#define TRACE_DDIO_WRITE__DONE(a0, a1, a2) do { } while (0)
#define TRACE_DDIO_SPARSE(a0, a1) do { } while (0)
#define TRACE_DDIO_SYNC__START(a0, a1) do { } while (0)
#define TRACE_DDIO_SYNC__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
