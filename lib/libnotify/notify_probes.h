/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFY_PROBES_H_
#define	_NOTIFY_PROBES_H_

#ifdef WITH_DTRACE
#include "notify_provider.h"
#define	NOTIFY_PROBE_RPC(a, b)	NOTIFY_RPC(a, b)
#define	NOTIFY_PROBE_PUBLISH(a, b, c)	NOTIFY_PUBLISH(a, b, c)
#define	NOTIFY_PROBE_NEXT(a, b)	NOTIFY_NEXT(a, b)
#define	NOTIFY_PROBE_REJECT(a, b)	NOTIFY_REJECT(a, b)
#define	NOTIFY_PROBE_RECONNECT(a, b)	NOTIFY_RECONNECT(a, b)
#else
#define	NOTIFY_PROBE_RPC(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFY_PROBE_PUBLISH(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	NOTIFY_PROBE_NEXT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFY_PROBE_REJECT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFY_PROBE_RECONNECT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#endif

#endif
