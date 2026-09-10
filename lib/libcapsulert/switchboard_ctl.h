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
/* Opcode 6 (SCTL_OP_PROVISION_SESSION) retired with the control socket. */
#define	SCTL_OP_RECLAIM		7	/* retire an uninstalled bundle label (root) */

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

/*
 * ----------------------------------------------------------------------------
 * Label-reclaim bridge (docs/capability-lifecycle-cleanup.md §5b).
 *
 * The SOLE deliberate UNIX-domain socket switchboard binds.  Its ONLY function is
 * to let a UNIX (non-plane) context — specifically a pkg(8) post-deinstall
 * script, which runs in a plain root context with no inherited ambient
 * discovery channel — trigger a bundle-label reclaim.  A pkg deinstall fork
 * has no ambient lookup fd (pkg preserves SERVICE_LOOKUP_FD in the environment
 * but closes the inherited descriptor), so it cannot reach switchboard's
 * SWITCHBOARD_CONTROL_NAME plane; this socket is the bridge.
 *
 * It grants NO new authority: root can already drive `switchboardctl reclaim` over
 * the ambient control channel from an admin login session (SCTL_OP_RECLAIM,
 * ADMIN-gated).  The socket is root-gated by getpeereid(2) (euid == 0); the
 * worst case it enables is a root-only DoS reclaiming a still-live label — a
 * capability root already holds by other means.  It performs reclaim and
 * nothing else: one fixed request in, one fixed reply out, connection closed.
 *
 * switchboard runs as uid 976 (capability:capability), so the socket node is
 * owned by 976 and chmod'd 0600.  root (pkg) can still connect — DAC
 * permission bits never restrict a privileged (uid 0) process — while any
 * other uid is refused at connect(2) by the 0600 mode AND, decisively, by the
 * getpeereid(2) euid == 0 gate on the server side.
 * ----------------------------------------------------------------------------
 */
#define	SWITCHBOARD_RECLAIM_SOCK		"/var/run/switchboard-reclaim.sock"
#define	SWITCHBOARD_RECLAIM_VERSION	1
#define	SWITCHBOARD_RECLAIM_LABEL_MAX	64	/* matches svc_reclaim_label_msg */

/*
 * Reclaim request: a fixed-size struct carrying one bundle label.  version
 * lets the wire contract evolve; label must be NUL-terminated within the field
 * and non-empty.
 */
struct switchboard_reclaim_req {
	uint32_t	version;	/* SWITCHBOARD_RECLAIM_VERSION */
	char		label[SWITCHBOARD_RECLAIM_LABEL_MAX];
} __packed;

/*
 * Reclaim reply: status is 0 on success or a positive errno (EPERM if the peer
 * was not root, EINVAL for a malformed request); providers_notified is the
 * count of running providers the SVC_OP_RECLAIM_LABEL push reached (meaningful
 * only when status == 0).
 */
struct switchboard_reclaim_reply {
	int32_t		status;		/* 0 = ok, else errno */
	uint32_t	providers_notified;
} __packed;

#endif /* SWITCHBOARD_CTL_H */
