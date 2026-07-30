/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _NETWORKCMP_PROVIDER_PROBES_H_
#define	_NETWORKCMP_PROVIDER_PROBES_H_

#ifdef WITH_DTRACE
#include "networkcmp_provider.h"
#else
#define	NETWORKCMP_PROVIDER_SESSION_START(l, n)	((void)0)
#define	NETWORKCMP_PROVIDER_RESOLVE_START(l, n)	((void)0)
#define	NETWORKCMP_PROVIDER_RESOLVE_DONE(l, n, e)	((void)0)
#define	NETWORKCMP_PROVIDER_REJECT(l, e)		((void)0)
#endif

#endif
