/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced control socket wire protocol.
 *
 * Used by servicectl(8) and future libraries to manage services.
 * One-shot connections: connect, send request, receive reply, close.
 */

#ifndef SERVICED_CTL_H
#define SERVICED_CTL_H

#include <sys/types.h>

/*
 * serviced's single control-plane rendezvous.  It lives on a private tmpfs at
 * serviced's runtime home (mounted by serviced before it binds), so no ZFS
 * snapshot or `zfs send` backup can ever capture the socket node and a reboot
 * leaves no stale node behind.  Override with SERVICED_CONTROL_SOCKET.
 */
#define	SERVICED_CTL_SOCK	"/Capabilities/serviced/control.sock"
/*
 * The capability control endpoint (capability-authority-model.md, P3).  serviced
 * self-serves this SYSTEM name over the ambient discovery plane; an admin login
 * session's lookup receives a channel carrying SVC_RIGHTS_ADMIN, which gates the
 * privileged control operations (reload/start/stop) in place of the socket's
 * getpeereid euid.  The one fd-passing op (PROVISION_SESSION) is not served here
 * and remains on the socket until the lifecycle phase (P4).
 */
#define	SERVICED_CONTROL_NAME	"system.serviced"
/*
 * The capability lifecycle endpoint (docs/lifecycle-capability-design.md, P4b).
 * serviced self-serves this SYSTEM name over the ambient discovery plane; an
 * admin login session's lookup receives an ADMIN-bearing channel over which
 * authorityctl(8) presents a lifecycle op (reboot/halt/...).  serviced relays the
 * op to authorityd (the spine, PID 1) rather than handling it itself.  The
 * everyday reboot/halt/shutdown(8) keep their stock BSD signal-to-init path.
 */
#define	SERVICED_LIFECYCLE_NAME	"system.lifecycle"
#define	SERVICED_CTL_VERSION	2
#define	SERVICED_CTL_MAX_PAYLOAD	1024
#define	SERVICED_CTL_SUMMARY_MAX	4096

/*
 * Control opcodes.
 */
#define	SCTL_OP_STATUS		1	/* query serviced status (any) */
#define	SCTL_OP_SERVICES	2	/* list loaded services (any) */
#define	SCTL_OP_RELOAD		3	/* reload manifests (root) */
#define	SCTL_OP_START_SVC	4	/* start a loaded unit (root) */
#define	SCTL_OP_STOP_SVC	5	/* stop a loaded unit (root) */
/*
 * SCTL_OP_PROVISION_SESSION — socket-authenticated session provisioning (§21/
 * §22, item 4).  ROOT ONLY: the handler requires the getpeereid(3)-attested
 * peer euid to be 0, since provisioning speaks for an arbitrary target uid.
 * The request payload is the target uid as a decimal ASCII string (no NUL, so
 * it passes the control channel's text-payload encoding check); serviced mints
 * the session lookup channel scoped by that TARGET uid — SYSTEM/admin for uid 0
 * or a wheel member, USER otherwise — and returns the caller's ambient,
 * CAP_XFER_ONCE endpoint attached to the reply via SCM_RIGHTS.  A non-root peer
 * gets EPERM and no fd.  This is the unified backend login(1)/su(1) provision
 * over getty inheritance; it exists for ssh network logins that cannot inherit
 * the SYSTEM channel.
 */
#define	SCTL_OP_PROVISION_SESSION	6	/* mint session channel for uid (root) */

struct sctl_request {
	uint32_t	version;
	uint32_t	op;
	uint32_t	flags;
	uint32_t	datalen;
} __packed;

/*
 * status is 0 on success or a positive errno.  flags carries the summary text
 * length that follows the reply header.  For SCTL_OP_PROVISION_SESSION a
 * successful reply carries no summary (flags == 0) and instead has the minted
 * session-channel descriptor attached to the reply header via SCM_RIGHTS; an
 * error reply carries a summary and no descriptor.
 */
struct sctl_reply {
	uint32_t	status;		/* 0 = ok, nonzero = errno */
	uint32_t	flags;		/* summary text length */
} __packed;

#endif /* SERVICED_CTL_H */
