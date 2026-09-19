/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACED_PROBES_H_
#define	_TRACED_PROBES_H_

#ifdef WITH_DTRACE
#include "traced_provider.h"
#define	TRACED_PROBE_SESSION_START(a, b, c) \
	TRACED_SESSION_START(a, b, c)
#define	TRACED_PROBE_SESSION_END(a, b, c) \
	TRACED_SESSION_END(a, b, c)
#define	TRACED_PROBE_DELEGATE(a, b, c)	TRACED_DELEGATE(a, b, c)
#define	TRACED_PROBE_REJECT(a, b, c)	TRACED_REJECT(a, b, c)
#else
#define	TRACED_PROBE_SESSION_START(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	TRACED_PROBE_SESSION_END(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	TRACED_PROBE_DELEGATE(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	TRACED_PROBE_REJECT(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#endif

#endif
