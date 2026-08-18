/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef PAM_GROUP_PROBES_H
#define PAM_GROUP_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) \
	do { if (0) { (void)(a); (void)(b); } } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) \
	do { if (0) { (void)(a); (void)(b); (void)(c); } } while (0)
#endif

#define PAM_GROUP_PROBE_SM_AUTHENTICATE(user,result) \
	DTRACE_PROBE2(pam_group, sm__authenticate, user, result)
#define PAM_GROUP_PROBE_SM_SETCRED(user,flags,result) \
	DTRACE_PROBE3(pam_group, sm__setcred, user, flags, result)
#define PAM_GROUP_PROBE_SM_ACCT_MGMT(user,result) \
	DTRACE_PROBE2(pam_group, sm__acct_mgmt, user, result)

#endif /* PAM_GROUP_PROBES_H */
