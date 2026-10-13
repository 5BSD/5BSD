/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _INSTALLCOPY_TRACE_H_
#define _INSTALLCOPY_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <installcopy_provider.h>

#define TRACE_INSTALLCOPY_RANGE__START(a0, a1) do { \
	if (INSTALLCOPY_RANGE_START_ENABLED()) \
		INSTALLCOPY_RANGE_START((int)(a0), (int)(a1)); \
} while (0)
#define TRACE_INSTALLCOPY_RANGE__DONE(a0, a1, a2, a3) do { \
	if (INSTALLCOPY_RANGE_DONE_ENABLED()) \
		INSTALLCOPY_RANGE_DONE((int)(a0), (int)(a1), (int64_t)(a2), (int)(a3)); \
} while (0)
#define TRACE_INSTALLCOPY_FALLBACK(a0, a1, a2) do { \
	if (INSTALLCOPY_FALLBACK_ENABLED()) \
		INSTALLCOPY_FALLBACK((int)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_INSTALLCOPY_SYNC__START(a0) do { \
	if (INSTALLCOPY_SYNC_START_ENABLED()) \
		INSTALLCOPY_SYNC_START((int)(a0)); \
} while (0)
#define TRACE_INSTALLCOPY_SYNC__DONE(a0, a1) do { \
	if (INSTALLCOPY_SYNC_DONE_ENABLED()) \
		INSTALLCOPY_SYNC_DONE((int)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_INSTALLCOPY_RANGE__START(a0, a1) do { } while (0)
#define TRACE_INSTALLCOPY_RANGE__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_INSTALLCOPY_FALLBACK(a0, a1, a2) do { } while (0)
#define TRACE_INSTALLCOPY_SYNC__START(a0) do { } while (0)
#define TRACE_INSTALLCOPY_SYNC__DONE(a0, a1) do { } while (0)
#endif
#endif
