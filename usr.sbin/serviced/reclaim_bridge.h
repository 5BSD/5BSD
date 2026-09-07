/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * serviced label-reclaim UNIX-socket bridge (docs/capability-lifecycle-cleanup.md
 * §5b).
 *
 * This is the SOLE deliberate UNIX-domain socket on the capability plane.  Its
 * one purpose is to let a pkg(8) post-deinstall script — a plain root context
 * with no inherited ambient discovery channel — trigger a bundle-label reclaim.
 * It confers NO new authority (root can already drive `servicectl reclaim` over
 * the ambient ADMIN control plane); it is root-gated by getpeereid(2) and does
 * reclaim and nothing else.  See the block comment at SERVICED_RECLAIM_SOCK in
 * serviced_ctl.h for the full rationale, and reclaim_bridge.c for the listener.
 *
 * The two predicates below are the single source of truth for the socket's
 * authorization and request-validation decisions, factored out so they are
 * pure, self-documenting, and unit-testable without a live daemon.
 */
#ifndef SERVICED_RECLAIM_BRIDGE_H
#define SERVICED_RECLAIM_BRIDGE_H

#include <sys/types.h>

#include <stdbool.h>
#include <string.h>

#include "serviced_ctl.h"		/* struct serviced_reclaim_req, *_reply */

/*
 * The reclaim bridge is authorized ONLY for a root peer.  Authority here is the
 * connecting process's effective uid (getpeereid(2)): euid == 0 is required.
 * This is deliberately a uid gate, not a held capability, because the bridge's
 * whole reason to exist is to serve a UNIX (non-plane) caller that has no
 * capability grant — the pkg deinstall context.  It grants nothing root cannot
 * already do over the ambient ADMIN control plane.
 */
static inline bool
reclaim_peer_is_authorized(uid_t peer_euid)
{

	return (peer_euid == 0);
}

/*
 * Whether a received reclaim request is well-formed: the version must match,
 * and the label must be non-empty and NUL-terminated within its fixed field
 * (so it fits svc_reclaim_label_msg.label with room for the terminator).  A
 * label with no NUL in the whole field, or an empty label, is rejected.
 */
static inline bool
reclaim_req_valid(const struct serviced_reclaim_req *req)
{
	const void *nul;

	if (req->version != SERVICED_RECLAIM_VERSION)
		return (false);
	nul = memchr(req->label, '\0', sizeof(req->label));
	if (nul == NULL)			/* not NUL-terminated in field */
		return (false);
	if (req->label[0] == '\0')		/* empty: nothing to reclaim */
		return (false);
	return (true);
}

/*
 * Action callback the serve routine invokes for a valid, authorized request:
 * perform the reclaim for `label` and return the number of providers notified.
 * Factored as a callback so reclaim_bridge_serve() is testable without the
 * daemon's svc_retire_label()/sd/serviced_kq.
 */
typedef unsigned (*reclaim_bridge_action)(const char *label, void *arg);

/*
 * Serve one already-accepted reclaim connection synchronously: read the fixed
 * request, apply the authorization decision (peer_authorized) and request
 * validation, invoke action() for a valid+authorized request, write the fixed
 * reply, and close connfd.  Returns 0 if a reply was written and the connection
 * closed cleanly, -1 on a transport error (connfd is still closed).  This is
 * the testable core shared by the production accept path and the unit test.
 */
int	reclaim_bridge_serve(int connfd, bool peer_authorized,
	    reclaim_bridge_action action, void *arg);

/* Best-effort listener lifecycle (serviced.c wires these into the event loop). */
int	reclaim_bridge_init(int kq);		/* create/bind/listen/register */
bool	reclaim_bridge_is_listener(int fd);	/* dispatch discrimination */
void	reclaim_bridge_accept(int kq);		/* listener became readable */
void	reclaim_bridge_teardown(void);		/* close listener, unlink node */

#endif /* SERVICED_RECLAIM_BRIDGE_H */
