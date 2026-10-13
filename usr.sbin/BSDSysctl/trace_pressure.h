/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef USR_SBIN_BSDSYSCTL_TRACE_PRESSURE_H
#define USR_SBIN_BSDSYSCTL_TRACE_PRESSURE_H
#ifdef WITH_DTRACE
#include "bsdsysctl_provider.h"
#endif
#ifdef WITH_DTRACE
#define BSDSYSCTL_TRACE_SESSION_LIMIT(a0, a1) \
	BSDSYSCTL_SESSION_LIMIT(a0, a1)
#else
#define BSDSYSCTL_TRACE_SESSION_LIMIT(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define BSDSYSCTL_TRACE_SESSION_OPEN_FAILURE(a0, a1) \
	BSDSYSCTL_SESSION_OPEN_FAILURE(a0, a1)
#else
#define BSDSYSCTL_TRACE_SESSION_OPEN_FAILURE(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#ifdef WITH_DTRACE
#define BSDSYSCTL_TRACE_SESSION_CLOSE_REASON(a0, a1) \
	BSDSYSCTL_SESSION_CLOSE_REASON(a0, a1)
#else
#define BSDSYSCTL_TRACE_SESSION_CLOSE_REASON(a0, a1) \
	do { if (0) { (void)(a0); (void)(a1); } } while (0)
#endif
#endif
