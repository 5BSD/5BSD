/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BSDNOTIFY_PROBES_H_
#define	_BSDNOTIFY_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdnotify_provider.h"
#define	BSDNOTIFY_PROBE_SESSION_START(a, b, c) \
	BSDNOTIFY_SESSION_START(a, b, c)
#define	BSDNOTIFY_PROBE_SESSION_END(a, b)	BSDNOTIFY_SESSION_END(a, b)
#define	BSDNOTIFY_PROBE_SUBSCRIBE(a, b, c)	BSDNOTIFY_SUBSCRIBE(a, b, c)
#define	BSDNOTIFY_PROBE_PUBLISH(a, b, c, d)	BSDNOTIFY_PUBLISH(a, b, c, d)
#define	BSDNOTIFY_PROBE_DELIVER(a, b, c)	BSDNOTIFY_DELIVER(a, b, c)
#define	BSDNOTIFY_PROBE_TIMER(a, b, c)	BSDNOTIFY_TIMER(a, b, c)
#define	BSDNOTIFY_PROBE_REJECT(a, b, c)	BSDNOTIFY_REJECT(a, b, c)
#define	BSDNOTIFY_PROBE_LIST(a, b, c)	BSDNOTIFY_LIST(a, b, c)
#else
#define	BSDNOTIFY_PROBE_SESSION_START(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDNOTIFY_PROBE_SESSION_END(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	BSDNOTIFY_PROBE_SUBSCRIBE(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDNOTIFY_PROBE_PUBLISH(a, b, c, d) \
	do { (void)(a); (void)(b); (void)(c); (void)(d); } while (0)
#define	BSDNOTIFY_PROBE_DELIVER(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDNOTIFY_PROBE_TIMER(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDNOTIFY_PROBE_REJECT(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	BSDNOTIFY_PROBE_LIST(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#endif

#endif
