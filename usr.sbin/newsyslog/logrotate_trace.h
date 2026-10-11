/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOGROTATE_TRACE_H_
#define _LOGROTATE_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <logrotate_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_logrotate_provider __attribute__((visibility("hidden")));
static const void * const logrotate_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_logrotate_provider;
#define TRACE_LOGROTATE_ROTATE__START(a0) do { \
	if (LOGROTATE_ROTATE_START_ENABLED()) \
		LOGROTATE_ROTATE_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_LOGROTATE_ROTATE__DONE(a0, a1) do { \
	if (LOGROTATE_ROTATE_DONE_ENABLED()) \
		LOGROTATE_ROTATE_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_LOGROTATE_COMPRESS__START(a0, a1) do { \
	if (LOGROTATE_COMPRESS_START_ENABLED()) \
		LOGROTATE_COMPRESS_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_LOGROTATE_COMPRESS__DONE(a0, a1, a2, a3) do { \
	if (LOGROTATE_COMPRESS_DONE_ENABLED()) \
		LOGROTATE_COMPRESS_DONE((uintptr_t)(a0), (int)(a1), (int)(a2), (int)(a3)); \
} while (0)
#define TRACE_LOGROTATE_NOTIFY(a0, a1, a2) do { \
	if (LOGROTATE_NOTIFY_ENABLED()) \
		LOGROTATE_NOTIFY((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_LOGROTATE_ROTATE__START(a0) do { } while (0)
#define TRACE_LOGROTATE_ROTATE__DONE(a0, a1) do { } while (0)
#define TRACE_LOGROTATE_COMPRESS__START(a0, a1) do { } while (0)
#define TRACE_LOGROTATE_COMPRESS__DONE(a0, a1, a2, a3) do { } while (0)
#define TRACE_LOGROTATE_NOTIFY(a0, a1, a2) do { } while (0)
#endif
#endif
