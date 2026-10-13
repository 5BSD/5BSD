/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBTIMECMP_DIAGNOSTICS_H
#define LIB_LIBTIMECMP_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define TIMECMP_TRACE_WAIT_START(a0) \
	DTRACE_PROBE1(timecmp, wait__start, (a0))
#else
#define TIMECMP_TRACE_WAIT_START(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#ifdef WITH_DTRACE
#define TIMECMP_TRACE_WAIT_DONE(a0, a1, a2) \
	DTRACE_PROBE3(timecmp, wait__done, (a0), (a1), (a2))
#else
#define TIMECMP_TRACE_WAIT_DONE(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define TIMECMP_TRACE_REPLY_MALFORMED(a0) \
	DTRACE_PROBE1(timecmp, reply__malformed, (a0))
#else
#define TIMECMP_TRACE_REPLY_MALFORMED(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#endif
