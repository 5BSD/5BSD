/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_CAPSULE_TRACE_PRESSURE_H
#define USR_SBIN_CAPSULE_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include <sys/sdt.h>
#endif
#ifdef WITH_DTRACE
#define CAPSULE_TRACE_CTL_ADMISSION_FAILURE(a0, a1, a2) \
	DTRACE_PROBE3(capsule, ctl__admission__failure, (a0), (a1), (a2))
#else
#define CAPSULE_TRACE_CTL_ADMISSION_FAILURE(a0, a1, a2) \
	do { if (0) { (void)(a0); (void)(a1); (void)(a2); } } while (0)
#endif
#ifdef WITH_DTRACE
#define CAPSULE_TRACE_CTL_TIMEOUT(a0) \
	DTRACE_PROBE1(capsule, ctl__timeout, (a0))
#else
#define CAPSULE_TRACE_CTL_TIMEOUT(a0) \
	do { if (0) { (void)(a0); } } while (0)
#endif
#endif
