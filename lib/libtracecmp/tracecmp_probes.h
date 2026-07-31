/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMP_PROBES_H_
#define	_TRACECMP_PROBES_H_

#ifdef WITH_DTRACE
#include "tracecmp_provider.h"
#define	TRACECMP_PROBE_OPEN(a, b)	TRACECMP_OPEN(a, b)
#define	TRACECMP_PROBE_SEND(a, b, c)	TRACECMP_SEND(a, b, c)
#define	TRACECMP_PROBE_RECEIVE(a, b, c)	TRACECMP_RECEIVE(a, b, c)
#define	TRACECMP_PROBE_REJECT(a, b)	TRACECMP_REJECT(a, b)
#else
#define	TRACECMP_PROBE_OPEN(a, b)	do { } while (0)
#define	TRACECMP_PROBE_SEND(a, b, c)	do { } while (0)
#define	TRACECMP_PROBE_RECEIVE(a, b, c)	do { } while (0)
#define	TRACECMP_PROBE_REJECT(a, b)	do { } while (0)
#endif

#endif
