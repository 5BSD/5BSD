/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for su(1).  Provider: su
 */

#ifndef SU_PROBES_H
#define SU_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#endif

#define	SU_PROBE_AUTH(from, to, tty, retcode)	\
	DTRACE_PROBE4(su, auth, from, to, tty, retcode)
#define	SU_PROBE_ACCT(to, retcode)	\
	DTRACE_PROBE2(su, acct, to, retcode)

#endif /* SU_PROBES_H */
