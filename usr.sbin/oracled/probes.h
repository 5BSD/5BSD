/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for oracled.
 *
 * Provider: oracled
 *
 * Usage:
 *   dtrace -n 'oracled*:::'           — trace all probes
 *   dtrace -n 'oracled*:::claim-*'    — trace claims
 *   dtrace -n 'oracled*:::ctl-*'      — trace control commands
 *   dtrace -n 'oracled*:::error'      — trace errors
 */

#ifndef PROBES_H
#define PROBES_H

#include <sys/sdt.h>

/* Lifecycle */
#define	ORACLED_PROBE_STARTUP()		\
	DTRACE_PROBE(oracled, startup)
#define	ORACLED_PROBE_SHUTDOWN(reason)	\
	DTRACE_PROBE1(oracled, shutdown, reason)
#define	ORACLED_PROBE_CONFIG(path)	\
	DTRACE_PROBE1(oracled, config__load, path)

/* Claims */
#define	ORACLED_PROBE_CLAIM_PATH(path)	\
	DTRACE_PROBE1(oracled, claim__path, path)
#define	ORACLED_PROBE_CLAIM_PATH_FAIL(path)	\
	DTRACE_PROBE1(oracled, claim__path__fail, path)
#define	ORACLED_PROBE_CLAIM_NET(port, proto)	\
	DTRACE_PROBE2(oracled, claim__net, port, proto)
#define	ORACLED_PROBE_CLAIM_NET_FAIL(port, proto)	\
	DTRACE_PROBE2(oracled, claim__net__fail, port, proto)

/* Integrity */
#define	ORACLED_PROBE_INTEGRITY(flags)	\
	DTRACE_PROBE1(oracled, integrity, flags)

/* Control socket */
#define	ORACLED_PROBE_CTL_ACCEPT(uid)	\
	DTRACE_PROBE1(oracled, ctl__accept, uid)
#define	ORACLED_PROBE_CTL_CMD(op, uid)	\
	DTRACE_PROBE2(oracled, ctl__cmd, op, uid)
#define	ORACLED_PROBE_CTL_DENY(op, uid)	\
	DTRACE_PROBE2(oracled, ctl__deny, op, uid)

/* Service lifecycle */
#define	ORACLED_PROBE_SVC_START(label, pid)	\
	DTRACE_PROBE2(oracled, svc__start, label, pid)
#define	ORACLED_PROBE_SVC_EXEC(label, pid)	\
	DTRACE_PROBE2(oracled, svc__exec, label, pid)
#define	ORACLED_PROBE_SVC_EXIT(label, pid, status)	\
	DTRACE_PROBE3(oracled, svc__exit, label, pid, status)
#define	ORACLED_PROBE_SVC_RESTART(label, count)	\
	DTRACE_PROBE2(oracled, svc__restart, label, count)

/* Reload and dynamic loading */
#define	ORACLED_PROBE_RELOAD()	\
	DTRACE_PROBE(oracled, reload)
#define	ORACLED_PROBE_SVC_LOAD(label)	\
	DTRACE_PROBE1(oracled, svc__load, label)

/* Errors */
#define	ORACLED_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(oracled, error, subsys, msg)

#endif /* PROBES_H */
