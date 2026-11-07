/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _THREADWAIT_TRACE_H_
#define _THREADWAIT_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <threadwait_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_threadwait_provider __attribute__((visibility("hidden")));
static const void * const threadwait_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_threadwait_provider;
#define TRACE_THREADWAIT_MUTEX__START(a0) do { \
	if (THREADWAIT_MUTEX_START_ENABLED()) \
		THREADWAIT_MUTEX_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_THREADWAIT_MUTEX__DONE(a0, a1) do { \
	if (THREADWAIT_MUTEX_DONE_ENABLED()) \
		THREADWAIT_MUTEX_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_CONDITION__START(a0, a1) do { \
	if (THREADWAIT_CONDITION_START_ENABLED()) \
		THREADWAIT_CONDITION_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_CONDITION__DONE(a0, a1) do { \
	if (THREADWAIT_CONDITION_DONE_ENABLED()) \
		THREADWAIT_CONDITION_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_JOIN__START(a0) do { \
	if (THREADWAIT_JOIN_START_ENABLED()) \
		THREADWAIT_JOIN_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_THREADWAIT_JOIN__DONE(a0, a1) do { \
	if (THREADWAIT_JOIN_DONE_ENABLED()) \
		THREADWAIT_JOIN_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)

#define TRACE_THREADWAIT_RWLOCK__START(a0, a1) do { \
	if (THREADWAIT_RWLOCK_START_ENABLED()) \
		THREADWAIT_RWLOCK_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_THREADWAIT_RWLOCK__DONE(a0, a1, a2) do { \
	if (THREADWAIT_RWLOCK_DONE_ENABLED()) \
		THREADWAIT_RWLOCK_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__ACQUIRE(a0, a1, a2) do { \
	if (PLOCKSTAT_MUTEX_ACQUIRE_ENABLED()) \
		PLOCKSTAT_MUTEX_ACQUIRE((void *)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__RELEASE(a0, a1) do { \
	if (PLOCKSTAT_MUTEX_RELEASE_ENABLED()) \
		PLOCKSTAT_MUTEX_RELEASE((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__BLOCK(a0) do { \
	if (PLOCKSTAT_MUTEX_BLOCK_ENABLED()) \
		PLOCKSTAT_MUTEX_BLOCK((void *)(a0)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__SPIN(a0) do { \
	if (PLOCKSTAT_MUTEX_SPIN_ENABLED()) \
		PLOCKSTAT_MUTEX_SPIN((void *)(a0)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__SPUN(a0, a1, a2) do { \
	if (PLOCKSTAT_MUTEX_SPUN_ENABLED()) \
		PLOCKSTAT_MUTEX_SPUN((void *)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__BLOCKED(a0, a1) do { \
	if (PLOCKSTAT_MUTEX_BLOCKED_ENABLED()) \
		PLOCKSTAT_MUTEX_BLOCKED((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_MUTEX__ERROR(a0, a1) do { \
	if (PLOCKSTAT_MUTEX_ERROR_ENABLED()) \
		PLOCKSTAT_MUTEX_ERROR((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_RW__ACQUIRE(a0, a1) do { \
	if (PLOCKSTAT_RW_ACQUIRE_ENABLED()) \
		PLOCKSTAT_RW_ACQUIRE((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_RW__RELEASE(a0, a1) do { \
	if (PLOCKSTAT_RW_RELEASE_ENABLED()) \
		PLOCKSTAT_RW_RELEASE((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_RW__BLOCK(a0, a1) do { \
	if (PLOCKSTAT_RW_BLOCK_ENABLED()) \
		PLOCKSTAT_RW_BLOCK((void *)(a0), (int)(a1)); \
} while (0)
#define TRACE_PLOCKSTAT_RW__BLOCKED(a0, a1, a2) do { \
	if (PLOCKSTAT_RW_BLOCKED_ENABLED()) \
		PLOCKSTAT_RW_BLOCKED((void *)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_PLOCKSTAT_RW__ERROR(a0, a1, a2) do { \
	if (PLOCKSTAT_RW_ERROR_ENABLED()) \
		PLOCKSTAT_RW_ERROR((void *)(a0), (int)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_PLOCKSTAT_MUTEX__ACQUIRE(a0, a1, a2) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__RELEASE(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__BLOCK(a0) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__SPIN(a0) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__SPUN(a0, a1, a2) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__BLOCKED(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_MUTEX__ERROR(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_RW__ACQUIRE(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_RW__RELEASE(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_RW__BLOCK(a0, a1) do { } while (0)
#define TRACE_PLOCKSTAT_RW__BLOCKED(a0, a1, a2) do { } while (0)
#define TRACE_PLOCKSTAT_RW__ERROR(a0, a1, a2) do { } while (0)
#define TRACE_THREADWAIT_RWLOCK__START(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_RWLOCK__DONE(a0, a1, a2) do { } while (0)
#define TRACE_THREADWAIT_MUTEX__START(a0) do { } while (0)
#define TRACE_THREADWAIT_MUTEX__DONE(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_CONDITION__START(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_CONDITION__DONE(a0, a1) do { } while (0)
#define TRACE_THREADWAIT_JOIN__START(a0) do { } while (0)
#define TRACE_THREADWAIT_JOIN__DONE(a0, a1) do { } while (0)
#endif
#endif
