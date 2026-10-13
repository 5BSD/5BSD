/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBOES_DIAGNOSTICS_H
#define LIB_LIBOES_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define OESCLIENT_TRACE_BATCH_READ(a0, a1) \
	DTRACE_PROBE2(oesclient, batch__read, (a0), (a1))
#else
#define OESCLIENT_TRACE_BATCH_READ(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define OESCLIENT_TRACE_BUFFER_CORRUPT(a0, a1) \
	DTRACE_PROBE2(oesclient, buffer__corrupt, (a0), (a1))
#else
#define OESCLIENT_TRACE_BUFFER_CORRUPT(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define OESCLIENT_TRACE_AUTH_RESPONSE(a0, a1, a2, a3) \
	DTRACE_PROBE4(oesclient, auth__response, (a0), (a1), (a2), (a3))
#else
#define OESCLIENT_TRACE_AUTH_RESPONSE(a0, a1, a2, a3) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); (void)(a3); } } while (0)
#endif
#endif
