/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * oracled control socket wire protocol.
 *
 * Shared between the daemon, oraclectl(8), and future libraries.
 *
 * This control socket is interim infrastructure.  The long-term
 * plan replaces it with cap_rt pair channels when oracled becomes
 * the system init.  Keep the protocol simple.
 *
 * Each connection is one-shot: connect, send request header
 * (plus optional payload), receive reply, close.
 */

#ifndef ORACLED_CTL_H
#define ORACLED_CTL_H

#include <sys/types.h>

#define	ORACLED_CTL_SOCK	"/var/run/oracled.sock"
#define	CTL_VERSION		1
#define	CTL_MAX_PAYLOAD		1024

/*
 * Control opcodes.
 */
#define	CTL_OP_SHUTDOWN		1	/* graceful shutdown (root) */
#define	CTL_OP_STATUS		2	/* query daemon status (any) */
#define	CTL_OP_RELOAD		3	/* reload configuration (root) */
#define	CTL_OP_KLDLOAD		4	/* load kernel module (root) */
#define	CTL_OP_KLDUNLOAD	5	/* unload kernel module (root) */
#define	CTL_OP_REBOOT		6	/* system reboot (root) */

/*
 * Request header.  For variable-length commands (kldload,
 * kldunload), datalen bytes of payload follow immediately
 * after the header.
 */
struct ctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;		/* op-specific (reboot howto) */
	uint32_t	datalen;	/* payload bytes following header */
} __packed;

#define	CTL_STATUS_OK		0

struct ctl_reply {
	uint32_t	status;		/* 0 = ok, nonzero = errno */
	uint32_t	flags;		/* op-specific */
	uint64_t	uptime_usec;	/* microseconds since start */
} __packed;

#endif /* ORACLED_CTL_H */
