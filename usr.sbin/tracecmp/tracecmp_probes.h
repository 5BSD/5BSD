/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _TRACECMPD_PROBES_H_
#define	_TRACECMPD_PROBES_H_

#ifdef WITH_DTRACE
#include "tracecmp_provider.h"
#define	TRACECMPD_PROBE_SESSION(a, b, c)	TRACECMPD_SESSION(a, b, c)
#define	TRACECMPD_PROBE_DELEGATE(a, b, c)	TRACECMPD_DELEGATE(a, b, c)
#define	TRACECMPD_PROBE_REJECT(a, b, c)	TRACECMPD_REJECT(a, b, c)
#else
#define	TRACECMPD_PROBE_SESSION(a, b, c)	do { } while (0)
#define	TRACECMPD_PROBE_DELEGATE(a, b, c)	do { } while (0)
#define	TRACECMPD_PROBE_REJECT(a, b, c)	do { } while (0)
#endif

#endif
