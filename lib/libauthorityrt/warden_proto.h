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
#define	WARDEN_OP_DESTROY_JAIL	2	/* remove the caller's jail */
#define	WARDEN_OP_LIST_JAILS	3	/* report the caller's jail */

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
 *
 * WARDEN_F_VNET — the jail gets its own virtual network stack (vnet=new), a
 * fully independent set of interfaces, addresses, and routing rather than a view
 * onto the host's stack restricted by ip4.addr/ip6.addr.  It is part of the
 * jail's immutable definition: a reuse whose vnet setting differs from the
 * existing jail's is a hard EEXIST, exactly like a path/hostname/address
 * mismatch.  Requires a VIMAGE kernel; on a kernel without it the create fails.
 */
#define	WARDEN_F_EPHEMERAL	0x1u
#define	WARDEN_F_VNET		0x2u

/*
 * Enter-jail request.  The jail is named and scoped by the caller's channel
 * label (warden derives it), so the request carries only the jail's shape.
 *
 * ip4_addr/ip6_addr are the jail's addresses on the host stack (empty = none of
 * that family).  With WARDEN_F_VNET the jail has its own stack instead; an
 * address may still be supplied to seed that stack.
 */
struct warden_request {
	uint32_t	op;			/* WARDEN_OP_ENTER_JAIL */
	uint32_t	flags;			/* WARDEN_F_* */
	char		path[PATH_MAX];		/* jail root path (required, /abs) */
	char		hostname[64];		/* host.hostname (empty=derived) */
	char		ip4_addr[64];		/* ip4.addr (empty=inherit) */
	char		ip6_addr[64];		/* ip6.addr (empty=none) */
};

/*
 * Reply.  On status==0 the message carries exactly one SCM descriptor: the
 * jail's NON-owning descriptor (jd) the caller jail_attach_jd(2)s itself to.
 * Closing it never removes the jail; an ephemeral jail is anchored instead by
 * the owning descriptor warden's per-client worker retains (see above).
 *
 * warden_reply is also the reply for WARDEN_OP_DESTROY_JAIL, which carries no
 * SCM fd (status only).
 */
struct warden_reply {
	int32_t		status;			/* 0, or errno */
	uint32_t	_reserved;
};

/*
 * Lifecycle-control request, for WARDEN_OP_DESTROY_JAIL and
 * WARDEN_OP_LIST_JAILS.  Both ops act on the ONE jail that the caller's
 * unforgeable channel label scopes (warden derives its name), so the request
 * carries no arguments beyond the opcode.  Neither op carries an SCM fd, in
 * either direction.
 *
 * Both are inherently OWNER-SCOPED: jail_name_from_label(caller) names exactly
 * one jail — the caller's own — so a caller can never name, enumerate, or
 * reclaim another label's jail.
 *
 * DESTROY removes the caller's jail (jail_remove(2)); it replies ENOENT if the
 * caller has no jail, and status 0 once the jail is gone.  If the target is an
 * ephemeral jail whose lifetime some worker anchors with an owning descriptor,
 * jail_remove still tears it down (prison_remove overrides that anchor).
 *
 * LIST reports the caller's jail definition: exactly zero or one jail, since a
 * label owns at most one.  present==1 with the fields filled when the caller has
 * a jail, present==0 when it has none; status is 0 in both cases, or an errno on
 * a real lookup failure.
 */
struct warden_control_request {
	uint32_t	op;			/* WARDEN_OP_DESTROY/LIST */
	uint32_t	_reserved;
};

/*
 * LIST reply.  present==1 means the caller has a jail and jid/path/hostname/
 * ip4_addr/ip6_addr/flags describe it (an address field is empty if the jail has
 * no address of that family); present==0 means the caller has no jail.  status is
 * 0 for both, or an errno on failure.
 *
 * `flags` carries the same WARDEN_F_* bits an ENTER would use to (re)create this
 * jail, so a consumer that LISTs after a restart can reconstruct a matching
 * request.  WARDEN_F_VNET is set when the jail has its own virtual network stack
 * (vnet=new); WARDEN_F_EPHEMERAL is set when this jail's lifetime is anchored by
 * warden's per-client worker serving THIS channel (an owning descriptor is held),
 * i.e. it is a jail this same connection created ephemerally — a persistent jail
 * reused across a consumer restart reports the flag clear, since no worker anchors
 * it.  (This field occupies what was a reserved word; the reply size is
 * unchanged, so it remains distinct from warden_reply for length dispatch.)
 */
struct warden_list_reply {
	int32_t		status;			/* 0, or errno */
	int32_t		present;		/* 1 = jail exists, 0 = none */
	int32_t		jid;			/* jail id when present */
	uint32_t	flags;			/* WARDEN_F_* describing the jail */
	char		path[PATH_MAX];		/* jail root path */
	char		hostname[64];		/* host.hostname */
	char		ip4_addr[64];		/* ip4.addr (empty if none) */
	char		ip6_addr[64];		/* ip6.addr (empty if none) */
};

#endif /* WARDEN_PROTO_H */
