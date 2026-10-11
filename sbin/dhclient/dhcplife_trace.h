/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _DHCPLIFE_TRACE_H_
#define _DHCPLIFE_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <dhcplife_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_dhcplife_provider __attribute__((visibility("hidden")));
static const void * const dhcplife_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_dhcplife_provider;
#define TRACE_DHCPLIFE_STATE(a0, a1) do { \
	if (DHCPLIFE_STATE_ENABLED()) \
		DHCPLIFE_STATE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_DHCPLIFE_SCRIPT__START(a0) do { \
	if (DHCPLIFE_SCRIPT_START_ENABLED()) \
		DHCPLIFE_SCRIPT_START((uintptr_t)(a0)); \
} while (0)
#define TRACE_DHCPLIFE_SCRIPT__DONE(a0, a1) do { \
	if (DHCPLIFE_SCRIPT_DONE_ENABLED()) \
		DHCPLIFE_SCRIPT_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#else
#define TRACE_DHCPLIFE_STATE(a0, a1) do { } while (0)
#define TRACE_DHCPLIFE_SCRIPT__START(a0) do { } while (0)
#define TRACE_DHCPLIFE_SCRIPT__DONE(a0, a1) do { } while (0)
#endif
#endif
