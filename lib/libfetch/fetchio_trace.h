/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FETCHIO_TRACE_H_
#define _FETCHIO_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <fetchio_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_fetchio_provider __attribute__((visibility("hidden")));
static const void * const fetchio_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_fetchio_provider;
#define TRACE_FETCHIO_REQUEST__START(a0) do { \
	if (FETCHIO_REQUEST_START_ENABLED()) \
		FETCHIO_REQUEST_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_FETCHIO_REQUEST__DONE(a0, a1, a2) do { \
	if (FETCHIO_REQUEST_DONE_ENABLED()) \
		FETCHIO_REQUEST_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_FETCHIO_CONNECT__START(a0, a1) do { \
	if (FETCHIO_CONNECT_START_ENABLED()) \
		FETCHIO_CONNECT_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_FETCHIO_CONNECT__DONE(a0, a1) do { \
	if (FETCHIO_CONNECT_DONE_ENABLED()) \
		FETCHIO_CONNECT_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_FETCHIO_TLS__START(a0) do { \
	if (FETCHIO_TLS_START_ENABLED()) \
		FETCHIO_TLS_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_FETCHIO_TLS__DONE(a0, a1) do { \
	if (FETCHIO_TLS_DONE_ENABLED()) \
		FETCHIO_TLS_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)

#define TRACE_FETCHIO_READ__START(a0, a1) do { \
	if (FETCHIO_READ_START_ENABLED()) \
		FETCHIO_READ_START((uintptr_t)(a0), (size_t)(a1)); \
} while (0)
#define TRACE_FETCHIO_READ__DONE(a0, a1, a2) do { \
	if (FETCHIO_READ_DONE_ENABLED()) \
		FETCHIO_READ_DONE((uintptr_t)(a0), (int64_t)(a1), (int)(a2)); \
} while (0)
#define TRACE_FETCHIO_WRITE__START(a0, a1) do { \
	if (FETCHIO_WRITE_START_ENABLED()) \
		FETCHIO_WRITE_START((uintptr_t)(a0), (size_t)(a1)); \
} while (0)
#define TRACE_FETCHIO_WRITE__DONE(a0, a1, a2) do { \
	if (FETCHIO_WRITE_DONE_ENABLED()) \
		FETCHIO_WRITE_DONE((uintptr_t)(a0), (int64_t)(a1), (int)(a2)); \
} while (0)
#define TRACE_FETCHIO_POLL__START(a0, a1, a2) do { \
	if (FETCHIO_POLL_START_ENABLED()) { \
		int trace_saved_errno = errno; \
		FETCHIO_POLL_START((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#define TRACE_FETCHIO_POLL__DONE(a0, a1, a2, a3) do { \
	if (FETCHIO_POLL_DONE_ENABLED()) { \
		int trace_saved_errno = errno; \
		FETCHIO_POLL_DONE((int)(a0), (int)(a1), (int)(a2), (int)(a3)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_FETCHIO_READ__START(a0, a1) do { } while (0)
#define TRACE_FETCHIO_READ__DONE(a0, a1, a2) do { } while (0)
#define TRACE_FETCHIO_WRITE__START(a0, a1) do { } while (0)
#define TRACE_FETCHIO_WRITE__DONE(a0, a1, a2) do { } while (0)
#define TRACE_FETCHIO_REQUEST__START(a0) do { } while (0)
#define TRACE_FETCHIO_REQUEST__DONE(a0, a1, a2) do { } while (0)
#define TRACE_FETCHIO_CONNECT__START(a0, a1) do { } while (0)
#define TRACE_FETCHIO_CONNECT__DONE(a0, a1) do { } while (0)
#define TRACE_FETCHIO_TLS__START(a0) do { } while (0)
#define TRACE_FETCHIO_TLS__DONE(a0, a1) do { } while (0)
#define TRACE_FETCHIO_POLL__START(a0, a1, a2) do { } while (0)
#define TRACE_FETCHIO_POLL__DONE(a0, a1, a2, a3) do { } while (0)
#endif
#endif
