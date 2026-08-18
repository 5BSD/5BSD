/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef PAM_RHOSTS_PROBES_H
#define PAM_RHOSTS_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) \
	do { if (0) { (void)(a); (void)(b); } } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) \
	do { if (0) { (void)(a); (void)(b); (void)(c); } } while (0)
#endif

#define PAM_RHOSTS_PROBE_SM_AUTHENTICATE(user,result) \
	DTRACE_PROBE2(pam_rhosts, sm__authenticate, user, result)
#define PAM_RHOSTS_PROBE_SM_SETCRED(user,flags,result) \
	DTRACE_PROBE3(pam_rhosts, sm__setcred, user, flags, result)

#endif /* PAM_RHOSTS_PROBES_H */
