/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for login(1).  Provider: login
 */

#ifndef LOGIN_PROBES_H
#define LOGIN_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#endif

#define	LOGIN_PROBE_AUTH(user, tty, rootlogin, retcode)	\
	DTRACE_PROBE4(login, auth, user, tty, rootlogin, retcode)
#define	LOGIN_PROBE_FAIL(user, tty)	\
	DTRACE_PROBE2(login, fail, user, tty)

#endif /* LOGIN_PROBES_H */
