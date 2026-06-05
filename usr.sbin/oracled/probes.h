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
 *   dtrace -n 'oracled*:::bootstrap-*' -- trace serviced lifecycle
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
#define	ORACLED_PROBE_CLAIM_PATH_RELEASE(path)	\
	DTRACE_PROBE1(oracled, claim__path__release, path)
#define	ORACLED_PROBE_CLAIM_NET(port_min, port_max, proto)	\
	DTRACE_PROBE3(oracled, claim__net, port_min, port_max, proto)
#define	ORACLED_PROBE_CLAIM_NET_FAIL(port_min, port_max, proto)	\
	DTRACE_PROBE3(oracled, claim__net__fail, port_min, port_max, proto)
#define	ORACLED_PROBE_CLAIM_NET_RELEASE(port_min, port_max, proto)	\
	DTRACE_PROBE3(oracled, claim__net__release, port_min, port_max, proto)
#define	ORACLED_PROBE_CLAIM_JAIL_RELEASE(name, actions)	\
	DTRACE_PROBE2(oracled, claim__jail__release, name, actions)
#define	ORACLED_PROBE_CLAIM_SYSTEM_RELEASE(gates)	\
	DTRACE_PROBE1(oracled, claim__system__release, gates)

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
#define	ORACLED_PROBE_RELOAD_CLAIMS_START(nacquire, nrelease)	\
	DTRACE_PROBE2(oracled, reload__claims__start, nacquire, nrelease)
#define	ORACLED_PROBE_RELOAD_CLAIMS_DONE(acquired, released, failed)	\
	DTRACE_PROBE3(oracled, reload__claims__done, acquired, released, failed)

/* Token minting — serviced requests capabilities for children */
#define	ORACLED_PROBE_MINT_PATH(path, result)	\
	DTRACE_PROBE2(oracled, mint__path, path, result)
#define	ORACLED_PROBE_MINT_NET(port_min, port_max, proto, result)	\
	DTRACE_PROBE4(oracled, mint__net, port_min, port_max, proto, result)
#define	ORACLED_PROBE_MINT_JAIL(jid, name, actions, result)	\
	DTRACE_PROBE4(oracled, mint__jail, jid, name, actions, result)
#define	ORACLED_PROBE_MINT_SYSTEM(gates, result)	\
	DTRACE_PROBE2(oracled, mint__system, gates, result)
#define	ORACLED_PROBE_CREATE_JAIL(name, result)	\
	DTRACE_PROBE2(oracled, create__jail, name, result)
#define	ORACLED_PROBE_PAIR_CREATE(result)	\
	DTRACE_PROBE1(oracled, pair__create, result)
#define	ORACLED_PROBE_COALITION_CREATE(result)	\
	DTRACE_PROBE1(oracled, coalition__create, result)

/* Oracle protocol IPC */
#define	ORACLED_PROBE_IPC_RECV(op)	\
	DTRACE_PROBE1(oracled, ipc__recv, op)
#define	ORACLED_PROBE_IPC_REPLY(op, status)	\
	DTRACE_PROBE2(oracled, ipc__reply, op, status)
#define	ORACLED_PROBE_IPC_DISPATCH_DONE(op, status, duration_ns)	\
	DTRACE_PROBE3(oracled, ipc__dispatch__done, op, status, duration_ns)

/* Bootstrap — serviced lifecycle */
#define	ORACLED_PROBE_BOOTSTRAP_START(pid)	\
	DTRACE_PROBE1(oracled, bootstrap__start, pid)
#define	ORACLED_PROBE_BOOTSTRAP_EXIT(pid, status)	\
	DTRACE_PROBE2(oracled, bootstrap__exit, pid, status)
#define	ORACLED_PROBE_BOOTSTRAP_RESTART(count, delay_sec)	\
	DTRACE_PROBE2(oracled, bootstrap__restart, count, delay_sec)

/* Connection tracking */
#define	ORACLED_PROBE_CONN_COUNT(nconns)	\
	DTRACE_PROBE1(oracled, conn__count, nconns)

/* Errors */
#define	ORACLED_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(oracled, error, subsys, msg)

#endif /* PROBES_H */
