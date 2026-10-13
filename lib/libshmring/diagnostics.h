/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef LIB_LIBSHMRING_DIAGNOSTICS_H
#define LIB_LIBSHMRING_DIAGNOSTICS_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define SHMRING_TRACE_RECORD_REJECT(a0, a1, a2) \
	DTRACE_PROBE3(shmring, record__reject, (a0), (a1), (a2))
#else
#define SHMRING_TRACE_RECORD_REJECT(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#endif
