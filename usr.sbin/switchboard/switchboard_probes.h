/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for switchboard.
 *
 * Provider: switchboard
 *
 * Usage:
 *   dtrace -n 'switchboard*:::'           -- trace all probes
 *   dtrace -n 'switchboard*:::svc-*'      -- trace service lifecycle
 *   dtrace -n 'switchboard*:::cap-*'      -- trace capability operations
 *   dtrace -n 'switchboard*:::naming-*'   -- trace naming registry
 *   dtrace -n 'switchboard*:::sctl-*'     -- trace control commands
 *   dtrace -n 'switchboard*:::ipc-*'      -- trace service IPC
 *   dtrace -n 'switchboard*:::timeout-*'  -- trace timer behavior
 */

#ifndef SWITCHBOARD_PROBES_H
#define SWITCHBOARD_PROBES_H

#ifdef WITH_DTRACE
#include <sys/sdt.h>
#else
/* No-op stubs when DTrace is disabled. */
#define	DTRACE_PROBE(provider, name)	((void)0)
#define	DTRACE_PROBE1(provider, name, arg1) \
	do { if (0) { (void)(arg1); } } while (0)
#define	DTRACE_PROBE2(provider, name, arg1, arg2) \
	do { if (0) { (void)(arg1); (void)(arg2); } } while (0)
#define	DTRACE_PROBE3(provider, name, arg1, arg2, arg3) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); } } while (0)
#define	DTRACE_PROBE4(provider, name, arg1, arg2, arg3, arg4) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); } } while (0)
#define DTRACE_PROBE5(provider, name, arg1, arg2, arg3, arg4, arg5) \
	do { if (0) { (void)(arg1); (void)(arg2); (void)(arg3); \
	    (void)(arg4); (void)(arg5); } } while (0)
#endif

#define SWITCHBOARD_PROBE_INSTALLATION(action, label, generation, state, error) \
	DTRACE_PROBE5(switchboard, installation, action, label, generation, state, error)

/* Service lifecycle */
#define	SWITCHBOARD_PROBE_SVC_START(label, pid)	\
	DTRACE_PROBE2(switchboard, svc__start, label, pid)
#define	SWITCHBOARD_PROBE_SVC_EXEC(label, pid)	\
	DTRACE_PROBE2(switchboard, svc__exec, label, pid)
#define	SWITCHBOARD_PROBE_SVC_CAPMODE(label, pid, protocol_ready)	\
	DTRACE_PROBE3(switchboard, svc__capmode, label, pid, protocol_ready)
#define	SWITCHBOARD_PROBE_SVC_EXIT(label, pid, status)	\
	DTRACE_PROBE3(switchboard, svc__exit, label, pid, status)
#define	SWITCHBOARD_PROBE_SVC_RESTART(label, count)	\
	DTRACE_PROBE2(switchboard, svc__restart, label, count)
#define	SWITCHBOARD_PROBE_SVC_STOP(label, pid)	\
	DTRACE_PROBE2(switchboard, svc__stop, label, pid)
#define	SWITCHBOARD_PROBE_SVC_LOAD(label)	\
	DTRACE_PROBE1(switchboard, svc__load, label)
#define	SWITCHBOARD_PROBE_SVC_DISABLED(label, count)	\
	DTRACE_PROBE2(switchboard, svc__disabled, label, count)

/* Manifest reload */
#define	SWITCHBOARD_PROBE_RELOAD(nnew, nchanged, nremoved)	\
	DTRACE_PROBE3(switchboard, reload, nnew, nchanged, nremoved)
#define	SWITCHBOARD_PROBE_SVC_REMOVED(label)	\
	DTRACE_PROBE1(switchboard, svc__removed, label)
#define	SWITCHBOARD_PROBE_SVC_CHANGED(label)	\
	DTRACE_PROBE1(switchboard, svc__changed, label)
/* label: retired bundle label; nservices: reclaim pushes emitted */
#define	SWITCHBOARD_PROBE_LABEL_RETIRED(label, nservices)	\
	DTRACE_PROBE2(switchboard, label__retired, label, nservices)

/* Naming registry */
#define	SWITCHBOARD_PROBE_NAMING_REGISTER(name, owner)	\
	DTRACE_PROBE2(switchboard, naming__register, name, owner)
#define	SWITCHBOARD_PROBE_NAMING_UNREGISTER(name)	\
	DTRACE_PROBE1(switchboard, naming__unregister, name)
#define	SWITCHBOARD_PROBE_NAMING_LOOKUP(name, requester)	\
	DTRACE_PROBE2(switchboard, naming__lookup, name, requester)
#define	SWITCHBOARD_PROBE_NAMING_DENY(name, err)	\
	DTRACE_PROBE2(switchboard, naming__deny, name, err)

/* Control socket */
#define	SWITCHBOARD_PROBE_SCTL_CMD(op, uid)	\
	DTRACE_PROBE2(switchboard, sctl__cmd, op, uid)
#define	SWITCHBOARD_PROBE_SCTL_CMD_DONE(op, uid, status, duration_ns)	\
	DTRACE_PROBE4(switchboard, sctl__cmd__done, op, uid, status, duration_ns)
#define	SWITCHBOARD_PROBE_SCTL_DENY(op, uid)	\
	DTRACE_PROBE2(switchboard, sctl__deny, op, uid)

/* Session-mint boundary (SVC_OP_MINT_DOMAIN, svc_proto.c) */
#define	SWITCHBOARD_PROBE_MINT_DOMAIN(label, kind, uid, result)	\
	DTRACE_PROBE4(switchboard, mint__domain, label, kind, uid, result)
#define	SWITCHBOARD_PROBE_MINT_DENY(label, domain, error)	\
	DTRACE_PROBE3(switchboard, mint__deny, label, domain, error)

/* Minted ambient/domain lookup channel (domain.c) */
#define	SWITCHBOARD_PROBE_DOMAIN_LOOKUP(name, kind, uid)	\
	DTRACE_PROBE3(switchboard, domain__lookup, name, kind, uid)
#define	SWITCHBOARD_PROBE_DOMAIN_LOOKUP_DENY(name, kind, error)	\
	DTRACE_PROBE3(switchboard, domain__lookup__deny, name, kind, error)

/*
 * IPC anointment refusal (anoint.c): the endpoint `name` requires names the
 * requester `label` does not hold; `missing` is the comma-separated list.
 * Fires next to the AUE_SWITCHBOARD_ANOINT audit record.
 */
#define	SWITCHBOARD_PROBE_ANOINT_DENY(name, label, missing)	\
	DTRACE_PROBE3(switchboard, anoint__deny, name, label, missing)

/* Per-service capability acquisition */
#define	SWITCHBOARD_PROBE_CAP_MINT(label, type, result)	\
	DTRACE_PROBE3(switchboard, cap__mint, label, type, result)
#define	SWITCHBOARD_PROBE_CAP_SERVICE(label, name, result)	\
	DTRACE_PROBE3(switchboard, cap__service, label, name, result)
#define	SWITCHBOARD_PROBE_CAP_CHANNEL(label, result)	\
	DTRACE_PROBE2(switchboard, cap__channel, label, result)
#define	SWITCHBOARD_PROBE_WORKER_CHANNEL(label, result)	\
	DTRACE_PROBE2(switchboard, worker__channel, label, result)
#define	SWITCHBOARD_PROBE_CAP_COALITION(label, result)	\
	DTRACE_PROBE2(switchboard, cap__coalition, label, result)
#define	SWITCHBOARD_PROBE_IDENTITY_VALIDATE(user, group, result)	\
	DTRACE_PROBE3(switchboard, identity__validate, user, group, result)

/* Service exec setup duration */
#define	SWITCHBOARD_PROBE_SVC_EXEC_DONE(label, duration_ns, ntokens)	\
	DTRACE_PROBE3(switchboard, svc__exec__done, label, duration_ns, ntokens)

/* Resource counts */
#define	SWITCHBOARD_PROBE_SVC_COUNT(nservices)	\
	DTRACE_PROBE1(switchboard, svc__count, nservices)
#define	SWITCHBOARD_PROBE_NAMING_COUNT(nnames)	\
	DTRACE_PROBE1(switchboard, naming__count, nnames)
#define	SWITCHBOARD_PROBE_FD_RESERVE(soft_limit, hard_limit, reserve_count)	\
	DTRACE_PROBE3(switchboard, fd__reserve, soft_limit, hard_limit, reserve_count)
#define	SWITCHBOARD_PROBE_FD_PRESSURE(purpose, required, denied)	\
	DTRACE_PROBE3(switchboard, fd__pressure, purpose, required, denied)

/* Service IPC — channel messages */
#define	SWITCHBOARD_PROBE_IPC_RECV(label, op)	\
	DTRACE_PROBE2(switchboard, ipc__recv, label, op)
#define	SWITCHBOARD_PROBE_IPC_REPLY(label, op, status)	\
	DTRACE_PROBE3(switchboard, ipc__reply, label, op, status)

/* Timeout tracking */
#define	SWITCHBOARD_PROBE_TIMEOUT_ARM(label, type, seconds)	\
	DTRACE_PROBE3(switchboard, timeout__arm, label, type, seconds)
#define	SWITCHBOARD_PROBE_TIMEOUT_FIRE(label, type)	\
	DTRACE_PROBE2(switchboard, timeout__fire, label, type)

/* Shutdown drain */
#define	SWITCHBOARD_PROBE_SHUTDOWN_START(nservices)	\
	DTRACE_PROBE1(switchboard, shutdown__start, nservices)
#define	SWITCHBOARD_PROBE_SHUTDOWN_DONE(duration_ns)	\
	DTRACE_PROBE1(switchboard, shutdown__done, duration_ns)
#define	SWITCHBOARD_PROBE_QUIESCE_REQUEST(label, reason, deadline_ms)	\
	DTRACE_PROBE3(switchboard, quiesce__request, label, reason, deadline_ms)
#define	SWITCHBOARD_PROBE_QUIESCE_COMPLETE(label, status)	\
	DTRACE_PROBE2(switchboard, quiesce__complete, label, status)

/* Connection tracking */
#define	SWITCHBOARD_PROBE_CONN_ACCEPT(uid, nconns)	\
	DTRACE_PROBE2(switchboard, conn__accept, uid, nconns)
#define	SWITCHBOARD_PROBE_CONN_CLOSE(nconns)	\
	DTRACE_PROBE1(switchboard, conn__close, nconns)

/* Startup orchestration */
#define	SWITCHBOARD_PROBE_STARTUP_BEGIN(nservices, ntiers)	\
	DTRACE_PROBE2(switchboard, startup__begin, nservices, ntiers)
#define	SWITCHBOARD_PROBE_STARTUP_TIER(tier, launched)	\
	DTRACE_PROBE2(switchboard, startup__tier, tier, launched)
#define	SWITCHBOARD_PROBE_STARTUP_DONE(duration_ms)	\
	DTRACE_PROBE1(switchboard, startup__done, duration_ms)

/* On-demand launch */
#define	SWITCHBOARD_PROBE_ON_DEMAND_LAUNCH(name, requester)	\
	DTRACE_PROBE2(switchboard, on__demand__launch, name, requester)
#define	SWITCHBOARD_PROBE_ON_DEMAND_COALESCE(name)	\
	DTRACE_PROBE1(switchboard, on__demand__coalesce, name)
#define	SWITCHBOARD_PROBE_ON_DEMAND_READY(name, nwaiters)	\
	DTRACE_PROBE2(switchboard, on__demand__ready, name, nwaiters)
#define	SWITCHBOARD_PROBE_ON_DEMAND_FAIL(name, error, nwaiters)	\
	DTRACE_PROBE3(switchboard, on__demand__fail, name, error, nwaiters)
#define	SWITCHBOARD_PROBE_ON_DEMAND_CANCEL(requester, pid, launch_id, nwaiters) \
	DTRACE_PROBE4(switchboard, on__demand__cancel, requester, pid, launch_id, \
	    nwaiters)
#define	SWITCHBOARD_PROBE_ON_DEMAND_TIMEOUT(name)	\
	DTRACE_PROBE1(switchboard, on__demand__timeout, name)
#define	SWITCHBOARD_PROBE_ENDPOINT_CLAIM(label, name, error)	\
	DTRACE_PROBE3(switchboard, endpoint__claim, label, name, error)
#define	SWITCHBOARD_PROBE_ENDPOINT_ACTIVATE(label, name)	\
	DTRACE_PROBE2(switchboard, endpoint__activate, label, name)
#define	SWITCHBOARD_PROBE_ENDPOINT_WITHDRAW(label, name, error)	\
	DTRACE_PROBE3(switchboard, endpoint__withdraw, label, name, error)

/* Bundle registry */
#define	SWITCHBOARD_PROBE_BUNDLE_LOAD(name, nservices, system)	\
	DTRACE_PROBE3(switchboard, bundle__load, name, nservices, system)
#define	SWITCHBOARD_PROBE_BUNDLE_SCAN(dir, nbundles)	\
	DTRACE_PROBE2(switchboard, bundle__scan, dir, nbundles)
#define	SWITCHBOARD_PROBE_MANIFEST_REJECT(path, reason, system)	\
	DTRACE_PROBE3(switchboard, manifest__reject, path, reason, system)

/* Errors */
#define	SWITCHBOARD_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(switchboard, error, subsys, msg)
#define	SWITCHBOARD_PROBE_SVC_EXEC_FAIL(label, error)	\
	DTRACE_PROBE2(switchboard, svc__exec__fail, label, error)
#define	SWITCHBOARD_PROBE_CAPSULE_DISCONNECTED()	\
	DTRACE_PROBE(switchboard, capsule__disconnected)

#endif /* SWITCHBOARD_PROBES_H */
