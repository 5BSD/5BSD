/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CPCOPY_TRACE_H_
#define _CPCOPY_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <cpcopy_provider.h>

#define TRACE_CPCOPY_TRANSFER__START(a0, a1) do { \
	if (CPCOPY_TRANSFER_START_ENABLED()) \
		CPCOPY_TRANSFER_START((int)(a0), (int)(a1)); \
} while (0)
#define TRACE_CPCOPY_TRANSFER__DONE(a0, a1, a2, a3) do { \
	if (CPCOPY_TRANSFER_DONE_ENABLED()) \
		CPCOPY_TRANSFER_DONE((int)(a0), (int)(a1), (int64_t)(a2), (int)(a3)); \
} while (0)
#define TRACE_CPCOPY_FALLBACK(a0, a1, a2) do { \
	if (CPCOPY_FALLBACK_ENABLED()) \
		CPCOPY_FALLBACK((int)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_CPCOPY_RETRY(a0, a1, a2) do { \
	if (CPCOPY_RETRY_ENABLED()) { \
		int trace_saved_errno = errno; \
		CPCOPY_RETRY((int)(a0), (int)(a1), (int)(a2)); \
		errno = trace_saved_errno; \
	} \
} while (0)
#else
#define TRACE_CPCOPY_TRANSFER__START(a0, a1) do { } while (0)
#define TRACE_CPCOPY_TRANSFER__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_CPCOPY_FALLBACK(a0, a1, a2) do { } while (0)
#define TRACE_CPCOPY_RETRY(a0, a1, a2) do { } while (0)
#endif
#endif
