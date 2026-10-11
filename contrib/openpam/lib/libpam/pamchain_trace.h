/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _PAMCHAIN_TRACE_H_
#define _PAMCHAIN_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <pamchain_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_pamchain_provider __attribute__((visibility("hidden")));
static const void * const pamchain_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_pamchain_provider;
#define TRACE_PAMCHAIN_CHAIN__START(a0, a1) do { \
	if (PAMCHAIN_CHAIN_START_ENABLED()) \
		PAMCHAIN_CHAIN_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_PAMCHAIN_CHAIN__DONE(a0, a1) do { \
	if (PAMCHAIN_CHAIN_DONE_ENABLED()) \
		PAMCHAIN_CHAIN_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_PAMCHAIN_MODULE__START(a0, a1, a2) do { \
	if (PAMCHAIN_MODULE_START_ENABLED()) \
		PAMCHAIN_MODULE_START((uintptr_t)(a0), (uintptr_t)(a1), (int)(a2)); \
} while (0)
#define TRACE_PAMCHAIN_MODULE__DONE(a0, a1, a2) do { \
	if (PAMCHAIN_MODULE_DONE_ENABLED()) \
		PAMCHAIN_MODULE_DONE((uintptr_t)(a0), (uintptr_t)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_PAMCHAIN_CHAIN__START(a0, a1) do { } while (0)
#define TRACE_PAMCHAIN_CHAIN__DONE(a0, a1) do { } while (0)
#define TRACE_PAMCHAIN_MODULE__START(a0, a1, a2) do { } while (0)
#define TRACE_PAMCHAIN_MODULE__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
