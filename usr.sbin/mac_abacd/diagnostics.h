/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_MAC_ABACD_DIAGNOSTICS_H
#define USR_SBIN_MAC_ABACD_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define ABACDAEMON_TRACE_POLICY_START(a0) \
	DTRACE_PROBE1(abacdaemon, policy__start, (a0))
#else
#define ABACDAEMON_TRACE_POLICY_START(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ABACDAEMON_TRACE_POLICY_DONE(a0, a1) \
	DTRACE_PROBE2(abacdaemon, policy__done, (a0), (a1))
#else
#define ABACDAEMON_TRACE_POLICY_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
