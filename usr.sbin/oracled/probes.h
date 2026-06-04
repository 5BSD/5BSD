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
 *   dtrace -n 'oracled*:::'           -- trace all probes
 *   dtrace -n 'oracled*:::claim-*'    -- trace authority claims
 *   dtrace -n 'oracled*:::mint-*'     -- trace token minting
 *   dtrace -n 'oracled*:::ctl-*'      -- trace control commands
 *   dtrace -n 'oracled*:::ipc-*'      -- trace oracle protocol
 *   dtrace -n 'oracled*:::error'      -- trace errors
 */

#ifndef PROBES_H
#define PROBES_H

#include <sys/sdt.h>

/* Lifecycle */
#define	ORACLED_PROBE_STARTUP()		\
	DTRACE_PROBE(oracled, startup)
#define	ORACLED_PROBE_SHUTDOWN(reason)	\
	DTRACE_PROBE1(oracled, shutdown, reason)
#define	ORACLED_PROBE_SHUTDOWN_DONE(duration_ns)	\
	DTRACE_PROBE1(oracled, shutdown__done, duration_ns)
#define	ORACLED_PROBE_CONFIG(path)	\
	DTRACE_PROBE1(oracled, config__load, path)

/* Claims — authority resource acquisition */
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
#define	ORACLED_PROBE_CTL_CMD_DONE(op, uid, status, duration_ns)	\
	DTRACE_PROBE4(oracled, ctl__cmd__done, op, uid, status, duration_ns)
#define	ORACLED_PROBE_CTL_DENY(op, uid)	\
	DTRACE_PROBE2(oracled, ctl__deny, op, uid)

/* Reload */
#define	ORACLED_PROBE_RELOAD()	\
	DTRACE_PROBE(oracled, reload)

/* Token minting — serviced requests capabilities for children */
#define	ORACLED_PROBE_MINT_PATH(path, result)	\
	DTRACE_PROBE2(oracled, mint__path, path, result)
#define	ORACLED_PROBE_MINT_NET(port, proto, result)	\
	DTRACE_PROBE3(oracled, mint__net, port, proto, result)
#define	ORACLED_PROBE_MINT_SYSTEM(gates, result)	\
	DTRACE_PROBE2(oracled, mint__system, gates, result)
#define	ORACLED_PROBE_PAIR_CREATE(result)	\
	DTRACE_PROBE1(oracled, pair__create, result)
#define	ORACLED_PROBE_COALITION_CREATE(result)	\
	DTRACE_PROBE1(oracled, coalition__create, result)

/* Oracle protocol IPC */
#define	ORACLED_PROBE_IPC_RECV(op)	\
	DTRACE_PROBE1(oracled, ipc__recv, op)
#define	ORACLED_PROBE_IPC_REPLY(op, status)	\
	DTRACE_PROBE2(oracled, ipc__reply, op, status)

/* Connection tracking */
#define	ORACLED_PROBE_CONN_COUNT(nconns)	\
	DTRACE_PROBE1(oracled, conn__count, nconns)

/* Errors */
#define	ORACLED_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(oracled, error, subsys, msg)

#endif /* PROBES_H */
