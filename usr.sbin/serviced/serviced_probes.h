/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * DTrace USDT probes for serviced.
 *
 * Provider: serviced
 *
 * Usage:
 *   dtrace -n 'serviced*:::'           -- trace all probes
 *   dtrace -n 'serviced*:::svc-*'      -- trace service lifecycle
 *   dtrace -n 'serviced*:::cap-*'      -- trace capability operations
 *   dtrace -n 'serviced*:::naming-*'   -- trace naming registry
 *   dtrace -n 'serviced*:::sctl-*'     -- trace control commands
 *   dtrace -n 'serviced*:::ipc-*'      -- trace service IPC
 *   dtrace -n 'serviced*:::timeout-*'  -- trace timer behavior
 */

#ifndef SERVICED_PROBES_H
#define SERVICED_PROBES_H

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
#endif

/* Service lifecycle */
#define	SERVICED_PROBE_SVC_START(label, pid)	\
	DTRACE_PROBE2(serviced, svc__start, label, pid)
#define	SERVICED_PROBE_SVC_EXEC(label, pid)	\
	DTRACE_PROBE2(serviced, svc__exec, label, pid)
#define	SERVICED_PROBE_SVC_CAPMODE(label, pid, protocol_ready)	\
	DTRACE_PROBE3(serviced, svc__capmode, label, pid, protocol_ready)
#define	SERVICED_PROBE_SVC_EXIT(label, pid, status)	\
	DTRACE_PROBE3(serviced, svc__exit, label, pid, status)
#define	SERVICED_PROBE_SVC_RESTART(label, count)	\
	DTRACE_PROBE2(serviced, svc__restart, label, count)
#define	SERVICED_PROBE_SVC_STOP(label, pid)	\
	DTRACE_PROBE2(serviced, svc__stop, label, pid)
#define	SERVICED_PROBE_SVC_LOAD(label)	\
	DTRACE_PROBE1(serviced, svc__load, label)
#define	SERVICED_PROBE_SVC_DISABLED(label, count)	\
	DTRACE_PROBE2(serviced, svc__disabled, label, count)

/* Manifest reload */
#define	SERVICED_PROBE_RELOAD(nnew, nchanged, nremoved)	\
	DTRACE_PROBE3(serviced, reload, nnew, nchanged, nremoved)
#define	SERVICED_PROBE_SVC_REMOVED(label)	\
	DTRACE_PROBE1(serviced, svc__removed, label)
#define	SERVICED_PROBE_SVC_CHANGED(label)	\
	DTRACE_PROBE1(serviced, svc__changed, label)

/* Naming registry */
#define	SERVICED_PROBE_NAMING_REGISTER(name, owner)	\
	DTRACE_PROBE2(serviced, naming__register, name, owner)
#define	SERVICED_PROBE_NAMING_UNREGISTER(name)	\
	DTRACE_PROBE1(serviced, naming__unregister, name)
#define	SERVICED_PROBE_NAMING_LOOKUP(name, requester)	\
	DTRACE_PROBE2(serviced, naming__lookup, name, requester)
#define	SERVICED_PROBE_NAMING_DENY(name, err)	\
	DTRACE_PROBE2(serviced, naming__deny, name, err)

/* Control socket */
#define	SERVICED_PROBE_SCTL_CMD(op, uid)	\
	DTRACE_PROBE2(serviced, sctl__cmd, op, uid)
#define	SERVICED_PROBE_SCTL_CMD_DONE(op, uid, status, duration_ns)	\
	DTRACE_PROBE4(serviced, sctl__cmd__done, op, uid, status, duration_ns)
#define	SERVICED_PROBE_SCTL_DENY(op, uid)	\
	DTRACE_PROBE2(serviced, sctl__deny, op, uid)

/* Per-service capability acquisition */
#define	SERVICED_PROBE_CAP_MINT(label, type, result)	\
	DTRACE_PROBE3(serviced, cap__mint, label, type, result)
#define	SERVICED_PROBE_CAP_SERVICE(label, name, result)	\
	DTRACE_PROBE3(serviced, cap__service, label, name, result)
#define	SERVICED_PROBE_CAP_CHANNEL(label, result)	\
	DTRACE_PROBE2(serviced, cap__channel, label, result)
#define	SERVICED_PROBE_WORKER_CHANNEL(label, result)	\
	DTRACE_PROBE2(serviced, worker__channel, label, result)
#define	SERVICED_PROBE_CAP_COALITION(label, result)	\
	DTRACE_PROBE2(serviced, cap__coalition, label, result)
#define	SERVICED_PROBE_IDENTITY_VALIDATE(user, group, result)	\
	DTRACE_PROBE3(serviced, identity__validate, user, group, result)

#define	SERVICED_PROBE_BOOTSTRAP_CREATE(label, ntokens, ndescs, result) \
	DTRACE_PROBE4(serviced, bootstrap__create, label, ntokens, ndescs, result)

/* Service exec setup duration */
#define	SERVICED_PROBE_SVC_EXEC_DONE(label, duration_ns, ntokens)	\
	DTRACE_PROBE3(serviced, svc__exec__done, label, duration_ns, ntokens)

/* Resource counts */
#define	SERVICED_PROBE_SVC_COUNT(nservices)	\
	DTRACE_PROBE1(serviced, svc__count, nservices)
#define	SERVICED_PROBE_NAMING_COUNT(nnames)	\
	DTRACE_PROBE1(serviced, naming__count, nnames)
#define	SERVICED_PROBE_FD_RESERVE(soft_limit, hard_limit, reserve_count)	\
	DTRACE_PROBE3(serviced, fd__reserve, soft_limit, hard_limit, reserve_count)
#define	SERVICED_PROBE_FD_PRESSURE(purpose, required, denied)	\
	DTRACE_PROBE3(serviced, fd__pressure, purpose, required, denied)

/* Service IPC — channel messages */
#define	SERVICED_PROBE_IPC_RECV(label, op)	\
	DTRACE_PROBE2(serviced, ipc__recv, label, op)
#define	SERVICED_PROBE_IPC_REPLY(label, op, status)	\
	DTRACE_PROBE3(serviced, ipc__reply, label, op, status)

/* Timeout tracking */
#define	SERVICED_PROBE_TIMEOUT_ARM(label, type, seconds)	\
	DTRACE_PROBE3(serviced, timeout__arm, label, type, seconds)
#define	SERVICED_PROBE_TIMEOUT_FIRE(label, type)	\
	DTRACE_PROBE2(serviced, timeout__fire, label, type)

/* Shutdown drain */
#define	SERVICED_PROBE_SHUTDOWN_START(nservices)	\
	DTRACE_PROBE1(serviced, shutdown__start, nservices)
#define	SERVICED_PROBE_SHUTDOWN_DONE(duration_ns)	\
	DTRACE_PROBE1(serviced, shutdown__done, duration_ns)
#define	SERVICED_PROBE_QUIESCE_REQUEST(label, reason, deadline_ms)	\
	DTRACE_PROBE3(serviced, quiesce__request, label, reason, deadline_ms)
#define	SERVICED_PROBE_QUIESCE_COMPLETE(label, status)	\
	DTRACE_PROBE2(serviced, quiesce__complete, label, status)

/* Connection tracking */
#define	SERVICED_PROBE_CONN_ACCEPT(uid, nconns)	\
	DTRACE_PROBE2(serviced, conn__accept, uid, nconns)
#define	SERVICED_PROBE_CONN_CLOSE(nconns)	\
	DTRACE_PROBE1(serviced, conn__close, nconns)

/* Startup orchestration */
#define	SERVICED_PROBE_STARTUP_BEGIN(nservices, ntiers)	\
	DTRACE_PROBE2(serviced, startup__begin, nservices, ntiers)
#define	SERVICED_PROBE_STARTUP_TIER(tier, launched)	\
	DTRACE_PROBE2(serviced, startup__tier, tier, launched)
#define	SERVICED_PROBE_STARTUP_DONE(duration_ms)	\
	DTRACE_PROBE1(serviced, startup__done, duration_ms)

/* On-demand launch */
#define	SERVICED_PROBE_ON_DEMAND_LAUNCH(name, requester)	\
	DTRACE_PROBE2(serviced, on__demand__launch, name, requester)
#define	SERVICED_PROBE_ON_DEMAND_COALESCE(name)	\
	DTRACE_PROBE1(serviced, on__demand__coalesce, name)
#define	SERVICED_PROBE_ON_DEMAND_READY(name, nwaiters)	\
	DTRACE_PROBE2(serviced, on__demand__ready, name, nwaiters)
#define	SERVICED_PROBE_ON_DEMAND_FAIL(name, error, nwaiters)	\
	DTRACE_PROBE3(serviced, on__demand__fail, name, error, nwaiters)
#define	SERVICED_PROBE_ON_DEMAND_CANCEL(requester, pid, launch_id, nwaiters) \
	DTRACE_PROBE4(serviced, on__demand__cancel, requester, pid, launch_id, \
	    nwaiters)
#define	SERVICED_PROBE_ON_DEMAND_TIMEOUT(name)	\
	DTRACE_PROBE1(serviced, on__demand__timeout, name)
#define	SERVICED_PROBE_ENDPOINT_CLAIM(label, name, error)	\
	DTRACE_PROBE3(serviced, endpoint__claim, label, name, error)
#define	SERVICED_PROBE_ENDPOINT_ACTIVATE(label, name)	\
	DTRACE_PROBE2(serviced, endpoint__activate, label, name)
#define	SERVICED_PROBE_ENDPOINT_WITHDRAW(label, name, error)	\
	DTRACE_PROBE3(serviced, endpoint__withdraw, label, name, error)

/* Bundle registry */
#define	SERVICED_PROBE_BUNDLE_LOAD(name, nservices, system)	\
	DTRACE_PROBE3(serviced, bundle__load, name, nservices, system)
#define	SERVICED_PROBE_BUNDLE_SCAN(dir, nbundles)	\
	DTRACE_PROBE2(serviced, bundle__scan, dir, nbundles)
#define	SERVICED_PROBE_MANIFEST_REJECT(path, reason, system)	\
	DTRACE_PROBE3(serviced, manifest__reject, path, reason, system)

/* Errors */
#define	SERVICED_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(serviced, error, subsys, msg)
#define	SERVICED_PROBE_SVC_EXEC_FAIL(label, error)	\
	DTRACE_PROBE2(serviced, svc__exec__fail, label, error)
#define	SERVICED_PROBE_AUTHORITY_DISCONNECTED()	\
	DTRACE_PROBE(serviced, authority__disconnected)

#endif /* SERVICED_PROBES_H */
