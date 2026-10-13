/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBCHANNEL_TRACE_PRESSURE_H
#define LIB_LIBCHANNEL_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define LIBCHANNEL_TRACE_QUEUE_LIMIT(a0, a1, a2) \
	DTRACE_PROBE3(libchannel, queue__limit, (a0), (a1), (a2))
#else
#define LIBCHANNEL_TRACE_QUEUE_LIMIT(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define LIBCHANNEL_TRACE_PENDING_LIMIT(a0, a1) \
	DTRACE_PROBE2(libchannel, pending__limit, (a0), (a1))
#else
#define LIBCHANNEL_TRACE_PENDING_LIMIT(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
