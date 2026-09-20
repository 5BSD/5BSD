/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BSDTRACE_PROBES_H_
#define	_BSDTRACE_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdtrace_provider.h"
#define	BSDTRACE_PROBE_SESSION_START(a, b, c) \
	BSDTRACE_SESSION_START(a, b, c)
#define	BSDTRACE_PROBE_SESSION_END(a, b, c) \
	BSDTRACE_SESSION_END(a, b, c)
#define	BSDTRACE_PROBE_DELEGATE(a, b, c)	BSDTRACE_DELEGATE(a, b, c)
#define	BSDTRACE_PROBE_REJECT(a, b, c)	BSDTRACE_REJECT(a, b, c)
#else
#define	BSDTRACE_PROBE_SESSION_START(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDTRACE_PROBE_SESSION_END(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDTRACE_PROBE_DELEGATE(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDTRACE_PROBE_REJECT(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#endif

#endif
