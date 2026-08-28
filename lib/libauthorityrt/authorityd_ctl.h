/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * authorityd control socket wire protocol.
 *
 * Shared between the daemon, authorityctl(8), and future libraries.
 *
 * The control socket handles administrative commands (status,
 * shutdown, reload).  Service management is handled by
 * serviced via servicectl(8).
 *
 * Each connection is one-shot: connect, send request header
 * (plus optional payload), receive reply, close.
 */

#ifndef AUTHORITYD_CTL_H
#define AUTHORITYD_CTL_H

#include <sys/types.h>

/* Default socket path — used by authorityctl to connect.
 * The daemon reads its actual path from config. */
#define	AUTHORITYD_CTL_SOCK	"/var/run/authorityd.sock"

#define	CTL_VERSION		1
#define	CTL_MAX_PAYLOAD		1024

/*
 * Control opcodes.
 *
 * Opcodes 7-9 (check, load, services) were removed — these
 * operations are handled by serviced via servicectl(8).
 * Do not reuse those numbers.
 */
#define	CTL_OP_SHUTDOWN		1	/* graceful shutdown (root) */
#define	CTL_OP_STATUS		2	/* query daemon status (any) */
#define	CTL_OP_RELOAD		3	/* reload configuration (root) */

/*
 * System lifecycle operations.  Valid only when authorityd is PID 1
 * (authority-init); an ordinary daemon rejects them with EPERM.  These
 * replace init(8)'s traditional signal ABI (see
 * docs/authority-control-abi-design.md).  All require root.  Opcodes 7-9
 * remain reserved (removed check/load/services); do not reuse them.
 */
#define	CTL_OP_REBOOT		4	/* reboot (RB_AUTOBOOT) */
#define	CTL_OP_HALT		5	/* halt (RB_HALT) */
#define	CTL_OP_POWEROFF		6	/* halt + power off */
#define	CTL_OP_POWERCYCLE	10	/* power-cycle */
#define	CTL_OP_SINGLE		11	/* shut down to single-user */
#define	CTL_OP_REROOT		12	/* root-filesystem reroot */
#define	CTL_OP_RESCAN		13	/* reread /etc/ttys (was SIGHUP) */
#define	CTL_OP_CATATONIA	14	/* stop new logins (was SIGTSTP) */

/*
 * Request header.  For variable-length commands, datalen bytes of
 * payload follow immediately after the header.
 */
struct ctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;		/* op-specific */
	uint32_t	datalen;	/* payload bytes following header */
} __packed;

#define	CTL_STATUS_OK		0
#define	CTL_SUMMARY_MAX		2048	/* max summary text */

struct ctl_reply {
	uint32_t	status;		/* 0 = ok, nonzero = errno */
	uint32_t	flags;		/* op-specific */
	uint64_t	uptime_usec;	/* microseconds since start */
} __packed;

#endif /* AUTHORITYD_CTL_H */
