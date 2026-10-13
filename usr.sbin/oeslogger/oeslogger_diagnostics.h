/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_OESLOGGER_DIAGNOSTICS_H
#define USR_SBIN_OESLOGGER_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define OESLOGGER_TRACE_EVENT_HANDLED(a0, a1) \
	DTRACE_PROBE2(oeslogger, event__handled, (a0), (a1))
#else
#define OESLOGGER_TRACE_EVENT_HANDLED(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define OESLOGGER_TRACE_WAIT_DONE(a0, a1) \
	DTRACE_PROBE2(oeslogger, wait__done, (a0), (a1))
#else
#define OESLOGGER_TRACE_WAIT_DONE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define OESLOGGER_TRACE_DISPATCH_ERROR(a0, a1) \
	DTRACE_PROBE2(oeslogger, dispatch__error, (a0), (a1))
#else
#define OESLOGGER_TRACE_DISPATCH_ERROR(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
