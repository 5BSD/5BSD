/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AUDITBROKERD_PROBES_H_
#define	_AUDITBROKERD_PROBES_H_

#ifdef WITH_DTRACE
#include "auditbrokerd_provider.h"
#define	AUDITBROKERD_PROBE_SESSION(a, b)	AUDITBROKERD_SESSION(a, b)
#define	AUDITBROKERD_PROBE_SUBMIT(a, b, c, d) \
	AUDITBROKERD_SUBMIT(a, b, c, d)
#define	AUDITBROKERD_PROBE_REJECT(a, b)	AUDITBROKERD_REJECT(a, b)
#else
#define	AUDITBROKERD_PROBE_SESSION(a, b)	do { } while (0)
#define	AUDITBROKERD_PROBE_SUBMIT(a, b, c, d)	do { } while (0)
#define	AUDITBROKERD_PROBE_REJECT(a, b)	do { } while (0)
#endif

#endif
