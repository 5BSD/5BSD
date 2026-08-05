/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LOCALNETWORK_PROBES_H_
#define	_LOCALNETWORK_PROBES_H_

#ifdef WITH_DTRACE
#include "localnetwork_provider.h"
#else
#define	LOCALNETWORK_SESSION_START(l, n)	((void)0)
#define	LOCALNETWORK_SESSION_END(l, e)	((void)0)
#define	LOCALNETWORK_REQUEST_DONE(l, o, e)	((void)0)
#define	LOCALNETWORK_RESOLVE_START(l, n)	((void)0)
#define	LOCALNETWORK_RESOLVE_DONE(l, n, e)	((void)0)
#define	LOCALNETWORK_REJECT(l, e)		((void)0)
#endif

#endif
