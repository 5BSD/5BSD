/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef PAM_LASTLOG_PROBES_H
#define PAM_LASTLOG_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) \
	do { if (0) { (void)(a); (void)(b); } } while (0)
#endif

#define PAM_LASTLOG_PROBE_SM_OPEN_SESSION(user,result) \
	DTRACE_PROBE2(pam_lastlog, sm__open_session, user, result)
#define PAM_LASTLOG_PROBE_SM_CLOSE_SESSION(user,result) \
	DTRACE_PROBE2(pam_lastlog, sm__close_session, user, result)

#endif /* PAM_LASTLOG_PROBES_H */
