/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_MAC_ABAC_CTL_DIAGNOSTICS_H
#define USR_SBIN_MAC_ABAC_CTL_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define ABACCTL_TRACE_POLICY_START(a0) \
	DTRACE_PROBE1(abacctl, policy__start, (a0))
#else
#define ABACCTL_TRACE_POLICY_START(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define ABACCTL_TRACE_POLICY_DONE(a0, a1) \
	DTRACE_PROBE2(abacctl, policy__done, (a0), (a1))
#else
#define ABACCTL_TRACE_POLICY_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
