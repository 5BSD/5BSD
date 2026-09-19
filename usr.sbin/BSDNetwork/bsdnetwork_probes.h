/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BSDNETWORK_PROBES_H_
#define	_BSDNETWORK_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdnetwork_provider.h"
#else
#define	BSDNETWORK_SESSION_START(l, n)	((void)0)
#define	BSDNETWORK_SESSION_END(l, e)	((void)0)
#define	BSDNETWORK_REQUEST_DONE(l, o, e)	((void)0)
#define	BSDNETWORK_RESOLVE_START(l, n)	((void)0)
#define	BSDNETWORK_RESOLVE_DONE(l, n, e)	((void)0)
/*
 * Connect outcome: label, "addr:port", requested timeout (ms; 0 = blocking),
 * and the errno-style result (0 = connected, ETIMEDOUT = timed out,
 * ECONNREFUSED = refused, other = failure).
 */
#define	BSDNETWORK_CONNECT_DONE(l, e, t, r)	((void)0)
#define	BSDNETWORK_REJECT(l, e)		((void)0)
#endif

#endif
