/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _AUTHAGENTD_PROBES_H_
#define	_AUTHAGENTD_PROBES_H_

#ifdef WITH_DTRACE
#include "authagentd_provider.h"
#define	AUTHAGENT_PROBE_REQUEST_START(client) \
	AUTHAGENT_REQUEST_START(__DECONST(char *, client))
#define	AUTHAGENT_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	AUTHAGENT_REQUEST_DONE(__DECONST(char *, client), uid, kind, flags, \
	    status, error)
#else
#define	AUTHAGENT_PROBE_REQUEST_START(client) \
	do { (void)(client); } while (0)
#define	AUTHAGENT_PROBE_REQUEST_DONE(client, uid, kind, flags, status, error) \
	do { (void)(client); (void)(uid); (void)(kind); (void)(flags); \
	    (void)(status); (void)(error); } while (0)
#endif

#endif /* !_AUTHAGENTD_PROBES_H_ */
