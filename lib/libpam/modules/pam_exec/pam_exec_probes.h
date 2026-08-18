/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef PAM_EXEC_PROBES_H
#define PAM_EXEC_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define DTRACE_PROBE2(p,n,a,b) \
	do { if (0) { (void)(a); (void)(b); } } while (0)
#define DTRACE_PROBE3(p,n,a,b,c) \
	do { if (0) { (void)(a); (void)(b); (void)(c); } } while (0)
#endif

#define PAM_EXEC_PROBE_SM_AUTHENTICATE(user,result) \
	DTRACE_PROBE2(pam_exec, sm__authenticate, user, result)
#define PAM_EXEC_PROBE_SM_SETCRED(user,flags,result) \
	DTRACE_PROBE3(pam_exec, sm__setcred, user, flags, result)
#define PAM_EXEC_PROBE_SM_ACCT_MGMT(user,result) \
	DTRACE_PROBE2(pam_exec, sm__acct_mgmt, user, result)
#define PAM_EXEC_PROBE_SM_OPEN_SESSION(user,result) \
	DTRACE_PROBE2(pam_exec, sm__open_session, user, result)
#define PAM_EXEC_PROBE_SM_CLOSE_SESSION(user,result) \
	DTRACE_PROBE2(pam_exec, sm__close_session, user, result)
#define PAM_EXEC_PROBE_SM_CHAUTHTOK(user,result) \
	DTRACE_PROBE2(pam_exec, sm__chauthtok, user, result)
#define PAM_EXEC_PROBE_EXEC(user,command) \
	DTRACE_PROBE2(pam_exec, exec, user, command)

#endif /* PAM_EXEC_PROBES_H */
