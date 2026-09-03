/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Wire protocol for warden(8) — the namespace (jail) broker.
 *
 * warden owns jail construction (jail_set(2)), taking it out of PID 1.  It is a
 * socket-free service_provider: a consumer reaches it over a held mac_capability
 * channel obtained by name (system.Namespace) and asks to enter a jail.  The
 * discovery domain layer resolves system.Namespace only for SYSTEM-domain
 * clients.
 *
 * This is consumer self-service, exactly like storage and module loading: a
 * program's library (service_enter_namespace(3)) — not serviced — resolves
 * warden and confines the process.  warden creates the jail rooted at the
 * requested path and returns a NON-owning descriptor as the reply's single SCM
 * fd; the *credential stored in that descriptor* (root, from warden) is what
 * authorizes jail_attach_jd(2), so the non-root consumer can attach itself.
 * Closing that descriptor never removes the jail.  For an ephemeral jail
 * (WARDEN_F_EPHEMERAL) warden instead retains a *separate* owning descriptor
 * (JAIL_OWN_DESC) in the per-client worker; libservice attaches with the
 * non-owning fd and closes it, and the worker's owning fd anchors the jail's
 * lifetime.  Self-jailing is self-confinement — a caller can only narrow
 * its own process — so warden needs no per-caller token: it scopes each jail by
 * the caller's unforgeable channel label, so one consumer can never name or
 * reuse another's jail.
 *
 * jail_set(2) needs the classic PRIV_JAIL_SET privilege and resolves the jail
 * root path against the global namespace, both of which capsicum forbids, so
 * warden — like sysextd — is a root, non-capability-mode privileged provider.
 */

#ifndef WARDEN_PROTO_H
#define WARDEN_PROTO_H

#include <sys/param.h>		/* PATH_MAX */

#include <stdint.h>

#define	WARDEN_SERVICE_NAME	"system.Namespace"

#define	WARDEN_OP_ENTER_JAIL	1	/* create/reuse the caller's jail */

/*
 * Request flags.
 *
 * WARDEN_F_EPHEMERAL — the jail's lifetime is bound to the consumer.  warden
 * retains a separate owning descriptor (JAIL_OWN_DESC) in the per-client worker
 * process serving this consumer; the consumer itself receives only the
 * non-owning descriptor (for its attach).  When the consumer disconnects the
 * worker exits, the owning descriptor closes, and the jail is torn down.  If
 * warden cannot acquire that owning descriptor it fails the request (and removes
 * the jail it just created) rather than silently leaving a permanent jail.
 * Without this flag the jail is persistent: it is created persist=1, reused by
 * label across consumer restarts, and outlives any single consumer.
 */
#define	WARDEN_F_EPHEMERAL	0x1u

/*
 * Enter-jail request.  The jail is named and scoped by the caller's channel
 * label (warden derives it), so the request carries only the jail's shape.
 */
struct warden_request {
	uint32_t	op;			/* WARDEN_OP_ENTER_JAIL */
	uint32_t	flags;			/* WARDEN_F_* */
	char		path[PATH_MAX];		/* jail root path (required, /abs) */
	char		hostname[64];		/* host.hostname (empty=derived) */
	char		ip4_addr[64];		/* ip4.addr (empty=inherit) */
};

/*
 * Reply.  On status==0 the message carries exactly one SCM descriptor: the
 * jail's NON-owning descriptor (jd) the caller jail_attach_jd(2)s itself to.
 * Closing it never removes the jail; an ephemeral jail is anchored instead by
 * the owning descriptor warden's per-client worker retains (see above).
 */
struct warden_reply {
	int32_t		status;			/* 0, or errno */
	uint32_t	_reserved;
};

#endif /* WARDEN_PROTO_H */
