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

#include <sys/sdt.h>

/* Service lifecycle */
#define	SERVICED_PROBE_SVC_START(label, pid)	\
	DTRACE_PROBE2(serviced, svc__start, label, pid)
#define	SERVICED_PROBE_SVC_EXEC(label, pid)	\
	DTRACE_PROBE2(serviced, svc__exec, label, pid)
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
#define	SERVICED_PROBE_CAP_PAIR(label, result)	\
	DTRACE_PROBE2(serviced, cap__pair, label, result)
#define	SERVICED_PROBE_CAP_COALITION(label, result)	\
	DTRACE_PROBE2(serviced, cap__coalition, label, result)

/* Service IPC — pair channel messages */
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

/* Connection tracking */
#define	SERVICED_PROBE_CONN_ACCEPT(uid, nconns)	\
	DTRACE_PROBE2(serviced, conn__accept, uid, nconns)
#define	SERVICED_PROBE_CONN_CLOSE(nconns)	\
	DTRACE_PROBE1(serviced, conn__close, nconns)

/* Errors */
#define	SERVICED_PROBE_ERROR(subsys, msg)	\
	DTRACE_PROBE2(serviced, error, subsys, msg)

#endif /* SERVICED_PROBES_H */
