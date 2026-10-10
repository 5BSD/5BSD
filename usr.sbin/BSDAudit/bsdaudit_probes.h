/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BSDAUDIT_PROBES_H_
#define	_BSDAUDIT_PROBES_H_

#ifdef WITH_DTRACE
#include "bsdaudit_provider.h"
#define BSDAUDIT_PROBE_REQUEST_DONE(op, status, error) \
	BSDAUDIT_REQUEST_DONE(op, status, error)
#define	BSDAUDIT_PROBE_SESSION(a, b)	BSDAUDIT_SESSION(a, b)
#define	BSDAUDIT_PROBE_SUBMIT(a, b, c, d) \
	BSDAUDIT_SUBMIT(a, b, c, d)
#define	BSDAUDIT_PROBE_REJECT(a, b)	BSDAUDIT_REJECT(a, b)
#else
#define BSDAUDIT_PROBE_REQUEST_DONE(op, status, error) \
	do { (void)(op); (void)(status); (void)(error); } while (0)
#define	BSDAUDIT_PROBE_SESSION(a, b)	do { } while (0)
#define	BSDAUDIT_PROBE_SUBMIT(a, b, c, d)	do { } while (0)
#define	BSDAUDIT_PROBE_REJECT(a, b)	do { } while (0)
#endif

#endif
