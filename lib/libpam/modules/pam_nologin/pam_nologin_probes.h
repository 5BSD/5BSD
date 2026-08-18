/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef PAM_NOLOGIN_PROBES_H
#define PAM_NOLOGIN_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) \
	do { if (0) { (void)(a); (void)(b); } } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) \
	do { if (0) { (void)(a); (void)(b); (void)(c); } } while (0)
#endif

#define PAM_NOLOGIN_PROBE_SM_ACCT_MGMT(user,result) \
	DTRACE_PROBE2(pam_nologin, sm__acct_mgmt, user, result)

#endif /* PAM_NOLOGIN_PROBES_H */
