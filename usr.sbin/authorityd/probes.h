/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for authorityd.
 *
 * Provider: authorityd
 *
 * Usage:
 *   dtrace -n 'authorityd*:::'           -- trace all probes
 *   dtrace -n 'authorityd*:::claim-*'    -- trace authority claims
 *   dtrace -n 'authorityd*:::mint-*'     -- trace token minting
 *   dtrace -n 'authorityd*:::ctl-*'      -- trace control commands
 *   dtrace -n 'authorityd*:::ipc-*'      -- trace authority protocol
 *   dtrace -n 'authorityd*:::bootstrap-*' -- trace serviced lifecycle
 *   dtrace -n 'authorityd*:::error'      -- trace errors
 */

#ifndef PROBES_H
#define PROBES_H

#include <sys/sdt.h>

/* Lifecycle */
#define	AUTHORITYD_PROBE_STARTUP()		\
	DTRACE_PROBE(authorityd, startup)
#define	AUTHORITYD_PROBE_SHUTDOWN(reason)	\
	DTRACE_PROBE1(authorityd, shutdown, reason)
#define	AUTHORITYD_PROBE_SHUTDOWN_DONE(duration_ns)	\
	DTRACE_PROBE1(authorityd, shutdown__done, duration_ns)
#define	AUTHORITYD_PROBE_CONFIG(path)	\
	DTRACE_PROBE1(authorityd, config__load, path)

/* Claims — authority resource acquisition */
#define	AUTHORITYD_PROBE_CLAIM_PATH(path)	\
	DTRACE_PROBE1(authorityd, claim__path, path)
#define	AUTHORITYD_PROBE_CLAIM_PATH_FAIL(path)	\
	DTRACE_PROBE1(authorityd, claim__path__fail, path)
#define	AUTHORITYD_PROBE_CLAIM_PATH_RELEASE(path)	\
	DTRACE_PROBE1(authorityd, claim__path__release, path)
#define	AUTHORITYD_PROBE_CLAIM_NET(port_min, port_max, proto)	\
	DTRACE_PROBE3(authorityd, claim__net, port_min, port_max, proto)
#define	AUTHORITYD_PROBE_CLAIM_NET_FAIL(port_min, port_max, proto)	\
	DTRACE_PROBE3(authorityd, claim__net__fail, port_min, port_max, proto)
#define	AUTHORITYD_PROBE_CLAIM_NET_RELEASE(port_min, port_max, proto)	\
	DTRACE_PROBE3(authorityd, claim__net__release, port_min, port_max, proto)
#define	AUTHORITYD_PROBE_CLAIM_JAIL_RELEASE(name, actions)	\
	DTRACE_PROBE2(authorityd, claim__jail__release, name, actions)
#define	AUTHORITYD_PROBE_CLAIM_SYSTEM_RELEASE(gates)	\
	DTRACE_PROBE1(authorityd, claim__system__release, gates)

/* Dynamic claims — runtime claim/release via channel */
#define	AUTHORITYD_PROBE_DYN_CLAIM_PATH(path, result)	\
	DTRACE_PROBE2(authorityd, dyn__claim__path, path, result)
#define	AUTHORITYD_PROBE_DYN_CLAIM_NET(port_min, port_max, proto, result)	\
	DTRACE_PROBE4(authorityd, dyn__claim__net, port_min, port_max, proto, result)
#define	AUTHORITYD_PROBE_DYN_CLAIM_JAIL(name, actions, result)	\
	DTRACE_PROBE3(authorityd, dyn__claim__jail, name, actions, result)
#define	AUTHORITYD_PROBE_DYN_CLAIM_SYSTEM(gates, result)	\
	DTRACE_PROBE2(authorityd, dyn__claim__system, gates, result)
#define	AUTHORITYD_PROBE_DYN_CLAIM_VSOCK(cid, pmin, pmax, result)	\
	DTRACE_PROBE4(authorityd, dyn__claim__vsock, cid, pmin, pmax, result)
#define	AUTHORITYD_PROBE_DYN_RELEASE_PATH(path, refcount, result)	\
	DTRACE_PROBE3(authorityd, dyn__release__path, path, refcount, result)
#define	AUTHORITYD_PROBE_DYN_RELEASE_NET(port_min, port_max, proto, refcount, result)	\
	DTRACE_PROBE5(authorityd, dyn__release__net, port_min, port_max, proto, refcount, result)
#define	AUTHORITYD_PROBE_DYN_RELEASE_JAIL(name, actions, refcount, result)	\
	DTRACE_PROBE4(authorityd, dyn__release__jail, name, actions, refcount, result)
#define	AUTHORITYD_PROBE_DYN_RELEASE_SYSTEM(gates, released, result)	\
	DTRACE_PROBE3(authorityd, dyn__release__system, gates, released, result)
#define	AUTHORITYD_PROBE_DYN_RELEASE_VSOCK(cid, pmin, pmax, refcount, result) \
	DTRACE_PROBE5(authorityd, dyn__release__vsock, cid, pmin, pmax, refcount, result)

/* Integrity */
#define	AUTHORITYD_PROBE_INTEGRITY(flags)	\
	DTRACE_PROBE1(authorityd, integrity, flags)

/* Control socket */
#define	AUTHORITYD_PROBE_CTL_ACCEPT(uid)	\
	DTRACE_PROBE1(authorityd, ctl__accept, uid)
#define	AUTHORITYD_PROBE_CTL_CMD(op, uid)	\
	DTRACE_PROBE2(authorityd, ctl__cmd, op, uid)
#define	AUTHORITYD_PROBE_CTL_CMD_DONE(op, uid, status, duration_ns)	\
	DTRACE_PROBE4(authorityd, ctl__cmd__done, op, uid, status, duration_ns)
#define	AUTHORITYD_PROBE_CTL_DENY(op, uid)	\
	DTRACE_PROBE2(authorityd, ctl__deny, op, uid)

/* Reload */
#define	AUTHORITYD_PROBE_RELOAD()	\
	DTRACE_PROBE(authorityd, reload)
#define	AUTHORITYD_PROBE_RELOAD_CLAIMS_START(nacquire, nrelease)	\
	DTRACE_PROBE2(authorityd, reload__claims__start, nacquire, nrelease)
#define	AUTHORITYD_PROBE_RELOAD_CLAIMS_DONE(acquired, released, failed)	\
	DTRACE_PROBE3(authorityd, reload__claims__done, acquired, released, failed)

/* Token minting — serviced requests capabilities for children */
#define	AUTHORITYD_PROBE_MINT_PATH(path, result)	\
	DTRACE_PROBE2(authorityd, mint__path, path, result)
#define	AUTHORITYD_PROBE_MINT_FILE(path, actions, result)	\
	DTRACE_PROBE3(authorityd, mint__file, path, actions, result)
#define	AUTHORITYD_PROBE_MINT_NET(port_min, port_max, proto, result)	\
	DTRACE_PROBE4(authorityd, mint__net, port_min, port_max, proto, result)
#define	AUTHORITYD_PROBE_MINT_JAIL(jid, name, actions, result)	\
	DTRACE_PROBE4(authorityd, mint__jail, jid, name, actions, result)
#define	AUTHORITYD_PROBE_MINT_SYSTEM(gates, result)	\
	DTRACE_PROBE2(authorityd, mint__system, gates, result)
#define	AUTHORITYD_PROBE_MINT_VSOCK(cid, pmin, pmax, result)	\
	DTRACE_PROBE4(authorityd, mint__vsock, cid, pmin, pmax, result)
#define	AUTHORITYD_PROBE_CHANNEL_CREATE(result)	\
	DTRACE_PROBE1(authorityd, channel__create, result)
#define	AUTHORITYD_PROBE_COALITION_CREATE(result)	\
	DTRACE_PROBE1(authorityd, coalition__create, result)
#define	AUTHORITYD_PROBE_SERVICE_DELEGATE(name, result)	\
	DTRACE_PROBE2(authorityd, service__delegate, name, result)

/* Authority protocol IPC */
#define	AUTHORITYD_PROBE_IPC_RECV(op)	\
	DTRACE_PROBE1(authorityd, ipc__recv, op)
#define	AUTHORITYD_PROBE_IPC_REPLY(op, status)	\
	DTRACE_PROBE2(authorityd, ipc__reply, op, status)
#define	AUTHORITYD_PROBE_IPC_DISPATCH_DONE(op, status, duration_ns)	\
	DTRACE_PROBE3(authorityd, ipc__dispatch__done, op, status, duration_ns)

/* Bootstrap — serviced lifecycle */
#define	AUTHORITYD_PROBE_BOOTSTRAP_START(pid)	\
	DTRACE_PROBE1(authorityd, bootstrap__start, pid)
#define	AUTHORITYD_PROBE_BOOTSTRAP_EXIT(pid, status)	\
	DTRACE_PROBE2(authorityd, bootstrap__exit, pid, status)
#define	AUTHORITYD_PROBE_BOOTSTRAP_RESTART(count, delay_sec)	\
	DTRACE_PROBE2(authorityd, bootstrap__restart, count, delay_sec)

/* Connection tracking */
#define	AUTHORITYD_PROBE_CONN_COUNT(nconns)	\
	DTRACE_PROBE1(authorityd, conn__count, nconns)

/* Errors */
#define	AUTHORITYD_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(authorityd, error, subsys, msg)

#endif /* PROBES_H */
