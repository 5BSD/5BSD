/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for capsule.
 *
 * Provider: capsule
 *
 * Usage:
 *   dtrace -n 'capsule*:::'           -- trace all probes
 *   dtrace -n 'capsule*:::claim-*'    -- trace Capsule claims
 *   dtrace -n 'capsule*:::mint-*'     -- trace token minting
 *   dtrace -n 'capsule*:::ctl-*'      -- trace control commands
 *   dtrace -n 'capsule*:::ipc-*'      -- trace Capsule protocol
 *   dtrace -n 'capsule*:::bootstrap-*' -- trace switchboard lifecycle
 *   dtrace -n 'capsule*:::error'      -- trace errors
 */

#ifndef PROBES_H
#define PROBES_H

#include <sys/sdt.h>

/* Lifecycle */
#define	CAPSULE_PROBE_STARTUP()		\
	DTRACE_PROBE(capsule, startup)
#define	CAPSULE_PROBE_SHUTDOWN(reason)	\
	DTRACE_PROBE1(capsule, shutdown, reason)
#define	CAPSULE_PROBE_SHUTDOWN_DONE(duration_ns)	\
	DTRACE_PROBE1(capsule, shutdown__done, duration_ns)
#define	CAPSULE_PROBE_CONFIG(path)	\
	DTRACE_PROBE1(capsule, config__load, path)

/* Claims — Capsule resource acquisition */
#define	CAPSULE_PROBE_CLAIM_PATH(path)	\
	DTRACE_PROBE1(capsule, claim__path, path)
#define	CAPSULE_PROBE_CLAIM_PATH_FAIL(path)	\
	DTRACE_PROBE1(capsule, claim__path__fail, path)
#define	CAPSULE_PROBE_CLAIM_NET(port_min, port_max, proto)	\
	DTRACE_PROBE3(capsule, claim__net, port_min, port_max, proto)
#define	CAPSULE_PROBE_CLAIM_NET_FAIL(port_min, port_max, proto)	\
	DTRACE_PROBE3(capsule, claim__net__fail, port_min, port_max, proto)
#define	CAPSULE_PROBE_CLAIM_NET_RELEASE(port_min, port_max, proto)	\
	DTRACE_PROBE3(capsule, claim__net__release, port_min, port_max, proto)
#define	CAPSULE_PROBE_CLAIM_SYSTEM_RELEASE(gates)	\
	DTRACE_PROBE1(capsule, claim__system__release, gates)

/* Dynamic claims — runtime claim/release via channel */
#define	CAPSULE_PROBE_DYN_CLAIM_NET(port_min, port_max, proto, result)	\
	DTRACE_PROBE4(capsule, dyn__claim__net, port_min, port_max, proto, result)
#define	CAPSULE_PROBE_DYN_CLAIM_SYSTEM(gates, result)	\
	DTRACE_PROBE2(capsule, dyn__claim__system, gates, result)
#define	CAPSULE_PROBE_DYN_CLAIM_VSOCK(cid, pmin, pmax, result)	\
	DTRACE_PROBE4(capsule, dyn__claim__vsock, cid, pmin, pmax, result)
#define	CAPSULE_PROBE_DYN_RELEASE_NET(port_min, port_max, proto, refcount, result)	\
	DTRACE_PROBE5(capsule, dyn__release__net, port_min, port_max, proto, refcount, result)
#define	CAPSULE_PROBE_DYN_RELEASE_SYSTEM(gates, released, result)	\
	DTRACE_PROBE3(capsule, dyn__release__system, gates, released, result)
#define	CAPSULE_PROBE_DYN_RELEASE_VSOCK(cid, pmin, pmax, refcount, result) \
	DTRACE_PROBE5(capsule, dyn__release__vsock, cid, pmin, pmax, refcount, result)

/* Integrity */
#define	CAPSULE_PROBE_INTEGRITY(flags)	\
	DTRACE_PROBE1(capsule, integrity, flags)

/* Control socket */
#define	CAPSULE_PROBE_CTL_ACCEPT(uid)	\
	DTRACE_PROBE1(capsule, ctl__accept, uid)
#define	CAPSULE_PROBE_CTL_CMD(op, uid)	\
	DTRACE_PROBE2(capsule, ctl__cmd, op, uid)
#define	CAPSULE_PROBE_CTL_CMD_DONE(op, uid, status, duration_ns)	\
	DTRACE_PROBE4(capsule, ctl__cmd__done, op, uid, status, duration_ns)
#define	CAPSULE_PROBE_CTL_DENY(op, uid)	\
	DTRACE_PROBE2(capsule, ctl__deny, op, uid)

/* Reload */
#define	CAPSULE_PROBE_RELOAD()	\
	DTRACE_PROBE(capsule, reload)
#define	CAPSULE_PROBE_RELOAD_CLAIMS_START(nacquire, nrelease)	\
	DTRACE_PROBE2(capsule, reload__claims__start, nacquire, nrelease)
#define	CAPSULE_PROBE_RELOAD_CLAIMS_DONE(acquired, released, failed)	\
	DTRACE_PROBE3(capsule, reload__claims__done, acquired, released, failed)

/* Token minting — switchboard requests capabilities for children */
#define	CAPSULE_PROBE_MINT_NET(port_min, port_max, proto, result)	\
	DTRACE_PROBE4(capsule, mint__net, port_min, port_max, proto, result)
#define	CAPSULE_PROBE_MINT_SYSTEM(gates, result)	\
	DTRACE_PROBE2(capsule, mint__system, gates, result)
#define	CAPSULE_PROBE_MINT_VSOCK(cid, pmin, pmax, result)	\
	DTRACE_PROBE4(capsule, mint__vsock, cid, pmin, pmax, result)
#define	CAPSULE_PROBE_CHANNEL_CREATE(result)	\
	DTRACE_PROBE1(capsule, channel__create, result)
#define	CAPSULE_PROBE_COALITION_CREATE(result)	\
	DTRACE_PROBE1(capsule, coalition__create, result)
#define	CAPSULE_PROBE_SERVICE_DELEGATE(name, result)	\
	DTRACE_PROBE2(capsule, service__delegate, name, result)

/* Capsule protocol IPC */
#define	CAPSULE_PROBE_IPC_RECV(op)	\
	DTRACE_PROBE1(capsule, ipc__recv, op)
#define	CAPSULE_PROBE_IPC_REPLY(op, status)	\
	DTRACE_PROBE2(capsule, ipc__reply, op, status)
#define	CAPSULE_PROBE_IPC_DISPATCH_DONE(op, status, duration_ns)	\
	DTRACE_PROBE3(capsule, ipc__dispatch__done, op, status, duration_ns)
#define	CAPSULE_PROBE_IPC_NONCE_MISMATCH(got, expected)	\
	DTRACE_PROBE2(capsule, ipc__nonce__mismatch, got, expected)

/* Bootstrap — switchboard lifecycle */
#define	CAPSULE_PROBE_BOOTSTRAP_START(pid)	\
	DTRACE_PROBE1(capsule, bootstrap__start, pid)
#define	CAPSULE_PROBE_BOOTSTRAP_EXIT(pid, status)	\
	DTRACE_PROBE2(capsule, bootstrap__exit, pid, status)
#define	CAPSULE_PROBE_BOOTSTRAP_RESTART(count, delay_sec)	\
	DTRACE_PROBE2(capsule, bootstrap__restart, count, delay_sec)

/* Connection tracking */
#define	CAPSULE_PROBE_CONN_COUNT(nconns)	\
	DTRACE_PROBE1(capsule, conn__count, nconns)

/*
 * Capsule — PID 1 boot/handoff/shutdown.  Only meaningful when capsule
 * runs as PID 1 (capsule.c); no-ops without DTrace exactly like the probes
 * above, since DTRACE_PROBE* expand to nothing when the .d provider is not
 * compiled in (MK_DTRACE=no).
 */
#define	CAPSULE_PROBE_CAPSULE_HANDOFF(kenv_value)	\
	DTRACE_PROBE1(capsule, capsule__handoff, kenv_value)
#define	CAPSULE_PROBE_CAPSULE_TRANSITION(state)	\
	DTRACE_PROBE1(capsule, capsule__transition, state)
#define	CAPSULE_PROBE_CAPSULE_REAPER_STATUS(flags, ok)	\
	DTRACE_PROBE2(capsule, capsule__reaper__status, flags, ok)
#define	CAPSULE_PROBE_CAPSULE_MAC_UP()	\
	DTRACE_PROBE(capsule, capsule__mac__up)
#define	CAPSULE_PROBE_CAPSULE_MAC_FAIL()	\
	DTRACE_PROBE(capsule, capsule__mac__fail)
#define	CAPSULE_PROBE_CAPSULE_SHIELD_RAISE()	\
	DTRACE_PROBE(capsule, capsule__shield__raise)
#define	CAPSULE_PROBE_CAPSULE_SHIELD_FAIL()	\
	DTRACE_PROBE(capsule, capsule__shield__fail)
#define	CAPSULE_PROBE_CAPSULE_ENGINE_UP(switchboard_pid)	\
	DTRACE_PROBE1(capsule, capsule__engine__up, switchboard_pid)
#define	CAPSULE_PROBE_CAPSULE_CONVERGE()	\
	DTRACE_PROBE(capsule, capsule__converge)
#define	CAPSULE_PROBE_CAPSULE_CONVERGE_FAIL()	\
	DTRACE_PROBE(capsule, capsule__converge__fail)
#define	CAPSULE_PROBE_CAPSULE_AMBIENT_INSTALL(fd, replaced)	\
	DTRACE_PROBE2(capsule, capsule__ambient__install, fd, replaced)
#define	CAPSULE_PROBE_CAPSULE_AMBIENT_FAIL(error)	\
	DTRACE_PROBE1(capsule, capsule__ambient__fail, error)
#define	CAPSULE_PROBE_CAPSULE_AMBIENT_CARRY(fd)	\
	DTRACE_PROBE1(capsule, capsule__ambient__carry, fd)
#define	CAPSULE_PROBE_CAPSULE_LIFECYCLE(op, howto, reboot, trans)	\
	DTRACE_PROBE4(capsule, capsule__lifecycle, op, howto, reboot, trans)
#define	CAPSULE_PROBE_CAPSULE_WORLD_STOP()	\
	DTRACE_PROBE(capsule, capsule__world__stop)
#define	CAPSULE_PROBE_CAPSULE_WORLD_KILL()	\
	DTRACE_PROBE(capsule, capsule__world__kill)
#define	CAPSULE_PROBE_CAPSULE_WORLD_STOPPED()	\
	DTRACE_PROBE(capsule, capsule__world__stopped)

/* Errors */
#define	CAPSULE_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(capsule, error, subsys, msg)

#endif /* PROBES_H */
