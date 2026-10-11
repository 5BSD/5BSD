/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SSHAUTH_TRACE_H_
#define _SSHAUTH_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <sshauth_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_sshauth_provider __attribute__((visibility("hidden")));
static const void * const sshauth_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_sshauth_provider;
#define TRACE_SSHAUTH_DECISION(a0, a1, a2, a3, a4) do { \
	if (SSHAUTH_DECISION_ENABLED()) \
		SSHAUTH_DECISION((uintptr_t)(a0), (int)(a1), (int)(a2), (int)(a3), (int)(a4)); \
} while (0)
#define TRACE_SSHAUTH_METHOD__START(a0, a1) do { \
	if (SSHAUTH_METHOD_START_ENABLED()) \
		SSHAUTH_METHOD_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_SSHAUTH_METHOD__DONE(a0, a1, a2) do { \
	if (SSHAUTH_METHOD_DONE_ENABLED()) \
		SSHAUTH_METHOD_DONE((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_SSHAUTH_DECISION(a0, a1, a2, a3, a4) do { } while (0)
#define TRACE_SSHAUTH_METHOD__START(a0, a1) do { } while (0)
#define TRACE_SSHAUTH_METHOD__DONE(a0, a1, a2) do { } while (0)
#endif
#endif
