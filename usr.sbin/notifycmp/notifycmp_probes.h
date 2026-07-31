/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NOTIFYCMPD_PROBES_H_
#define	_NOTIFYCMPD_PROBES_H_

#ifdef WITH_DTRACE
#include "notifycmp_provider.h"
#define	NOTIFYCMPD_PROBE_SESSION(a, b, c)	NOTIFYCMPD_SESSION(a, b, c)
#define	NOTIFYCMPD_PROBE_SUBSCRIBE(a, b, c)	NOTIFYCMPD_SUBSCRIBE(a, b, c)
#define	NOTIFYCMPD_PROBE_PUBLISH(a, b, c, d)	NOTIFYCMPD_PUBLISH(a, b, c, d)
#define	NOTIFYCMPD_PROBE_DELIVER(a, b, c)	NOTIFYCMPD_DELIVER(a, b, c)
#define	NOTIFYCMPD_PROBE_TIMER(a, b, c)	NOTIFYCMPD_TIMER(a, b, c)
#define	NOTIFYCMPD_PROBE_REJECT(a, b, c)	NOTIFYCMPD_REJECT(a, b, c)
#else
#define	NOTIFYCMPD_PROBE_SESSION(a, b, c)	((void)0)
#define	NOTIFYCMPD_PROBE_SUBSCRIBE(a, b, c)	((void)0)
#define	NOTIFYCMPD_PROBE_PUBLISH(a, b, c, d)	((void)0)
#define	NOTIFYCMPD_PROBE_DELIVER(a, b, c)	((void)0)
#define	NOTIFYCMPD_PROBE_TIMER(a, b, c)	((void)0)
#define	NOTIFYCMPD_PROBE_REJECT(a, b, c)	((void)0)
#endif

#endif
