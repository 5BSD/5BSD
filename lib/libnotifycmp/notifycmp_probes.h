/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMP_PROBES_H_
#define	_NOTIFYCMP_PROBES_H_

#ifdef WITH_DTRACE
#include "notifycmp_provider.h"
#define	NOTIFYCMP_PROBE_RPC(a, b)	NOTIFYCMP_RPC(a, b)
#define	NOTIFYCMP_PROBE_PUBLISH(a, b, c)	NOTIFYCMP_PUBLISH(a, b, c)
#define	NOTIFYCMP_PROBE_NEXT(a, b)	NOTIFYCMP_NEXT(a, b)
#define	NOTIFYCMP_PROBE_REJECT(a, b)	NOTIFYCMP_REJECT(a, b)
#define	NOTIFYCMP_PROBE_RECONNECT(a, b)	NOTIFYCMP_RECONNECT(a, b)
#else
#define	NOTIFYCMP_PROBE_RPC(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFYCMP_PROBE_PUBLISH(a, b, c) \
	do { (void)(a); (void)(b); (void)(c); } while (0)
#define	NOTIFYCMP_PROBE_NEXT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFYCMP_PROBE_REJECT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#define	NOTIFYCMP_PROBE_RECONNECT(a, b) \
	do { (void)(a); (void)(b); } while (0)
#endif

#endif
