/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * switchboard control socket wire protocol.
 *
 * Used by switchboardctl(8) and future libraries to manage services.
 * One-shot connections: connect, send request, receive reply, close.
 */

#ifndef SWITCHBOARD_CTL_H
#define SWITCHBOARD_CTL_H

#include <sys/types.h>

/*
 * The capability control endpoint (capability-authority-model.md, P3).  switchboard
 * self-serves this SYSTEM name over the ambient discovery plane; an admin login
 * session's lookup receives a channel carrying SVC_RIGHTS_ADMIN, which gates the
 * privileged control operations (reload/start/stop).  This is the ONLY control
 * transport: the getpeereid(2) control socket was retired, and session
 * provisioning now mints over each caller's inherited/own SYSTEM channel.
 */
#define	SWITCHBOARD_CONTROL_NAME	"system.switchboard"
/*
 * The capability lifecycle endpoint (docs/lifecycle-capability-design.md, P4b).
 * switchboard self-serves this SYSTEM name over the ambient discovery plane; an
 * admin login session's lookup receives an ADMIN-bearing channel over which
 * capsulectl(8) presents a lifecycle op (reboot/halt/...).  switchboard relays the
 * op to capsule (the spine, PID 1) rather than handling it itself.  The
 * everyday reboot/halt/shutdown(8) keep their stock BSD signal-to-init path.
 */
#define	SWITCHBOARD_LIFECYCLE_NAME	"system.lifecycle"
#define	SWITCHBOARD_CTL_VERSION	2
#define	SWITCHBOARD_CTL_MAX_PAYLOAD	1024
#define	SWITCHBOARD_CTL_SUMMARY_MAX	4096

/*
 * Control opcodes.
 */
#define	SCTL_OP_STATUS		1	/* query switchboard status (any) */
#define	SCTL_OP_SERVICES	2	/* list loaded services (any) */
#define	SCTL_OP_RELOAD		3	/* reload manifests (root) */
#define	SCTL_OP_START_SVC	4	/* start a loaded unit (root) */
#define	SCTL_OP_STOP_SVC	5	/* stop a loaded unit (root) */

struct sctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	datalen;
} __packed;

/*
 * status is 0 on success or a positive errno.  flags carries the summary text
 * length that follows the reply header.
 */
struct sctl_reply {
	uint32_t	status;		/* 0 = ok, nonzero = errno */
	uint32_t	flags;		/* summary text length */
} __packed;

#endif /* SWITCHBOARD_CTL_H */
