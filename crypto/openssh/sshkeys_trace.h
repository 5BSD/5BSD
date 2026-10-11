/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _SSHKEYS_TRACE_H_
#define _SSHKEYS_TRACE_H_

#ifdef WITH_COVERAGE_DTRACE
#include <sshkeys_provider.h>
/* Keep provider metadata when this translation unit comes from an archive. */
extern const unsigned char __bsd_dof_anchor_sshkeys_provider __attribute__((visibility("hidden")));
static const void * const sshkeys_dtrace_anchor __attribute__((used, retain)) =
    &__bsd_dof_anchor_sshkeys_provider;
#define TRACE_SSHKEYS_NEWKEYS__START(a0, a1) do { \
	if (SSHKEYS_NEWKEYS_START_ENABLED()) \
		SSHKEYS_NEWKEYS_START((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_SSHKEYS_NEWKEYS__DONE(a0, a1) do { \
	if (SSHKEYS_NEWKEYS_DONE_ENABLED()) \
		SSHKEYS_NEWKEYS_DONE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_SSHKEYS_CHANNEL__NEW(a0, a1, a2) do { \
	if (SSHKEYS_CHANNEL_NEW_ENABLED()) \
		SSHKEYS_CHANNEL_NEW((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#define TRACE_SSHKEYS_CHANNEL__FREE(a0, a1) do { \
	if (SSHKEYS_CHANNEL_FREE_ENABLED()) \
		SSHKEYS_CHANNEL_FREE((uintptr_t)(a0), (int)(a1)); \
} while (0)
#define TRACE_SSHKEYS_CHANNEL__REPLY(a0, a1, a2) do { \
	if (SSHKEYS_CHANNEL_REPLY_ENABLED()) \
		SSHKEYS_CHANNEL_REPLY((uintptr_t)(a0), (int)(a1), (int)(a2)); \
} while (0)
#else
#define TRACE_SSHKEYS_NEWKEYS__START(a0, a1) do { } while (0)
#define TRACE_SSHKEYS_NEWKEYS__DONE(a0, a1) do { } while (0)
#define TRACE_SSHKEYS_CHANNEL__NEW(a0, a1, a2) do { } while (0)
#define TRACE_SSHKEYS_CHANNEL__FREE(a0, a1) do { } while (0)
#define TRACE_SSHKEYS_CHANNEL__REPLY(a0, a1, a2) do { } while (0)
#endif
#endif
