/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Reclaim-bridge unit tests (docs/capability-lifecycle-cleanup.md §5b).
 *
 * The reclaim bridge is the sole deliberate UNIX socket on the plane; its ONLY
 * function is to let a UNIX (pkg deinstall) context trigger a bundle-label
 * reclaim, root-gated by getpeereid(2).  This pins three decisions without a
 * live switchboard:
 *
 *  1. reclaim_peer_is_authorized() — only euid == 0 may drive reclaim.
 *  2. reclaim_req_valid()          — version + non-empty, NUL-terminated label.
 *  3. reclaim_bridge_serve()       — the end-to-end accept-side request/reply
 *     over a real connected socket: an authorized+valid request invokes the
 *     action and reports its provider count; an unauthorized peer is EPERM'd
 *     and the action never runs; a malformed request is EINVAL'd.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "switchboard_ctl.h"
#include "reclaim_bridge.h"

/* ---- Guard 1: the getpeereid authorization decision (uid gate). ---- */
ATF_TC_WITHOUT_HEAD(peer_authorized_root_only);
ATF_TC_BODY(peer_authorized_root_only, tc)
{

	ATF_CHECK_MSG(reclaim_peer_is_authorized(0),
	    "root (euid 0) must be authorized for reclaim");
	ATF_CHECK_MSG(!reclaim_peer_is_authorized(1),
	    "uid 1 must not be authorized");
	ATF_CHECK_MSG(!reclaim_peer_is_authorized(976),
	    "the switchboard uid (976) is not root and must not be authorized");
	ATF_CHECK_MSG(!reclaim_peer_is_authorized(1000),
	    "an ordinary user must not be authorized");
}

/* ---- Guard 2: request validation edges. ---- */
ATF_TC_WITHOUT_HEAD(req_validation_edges);
ATF_TC_BODY(req_validation_edges, tc)
{
	struct switchboard_reclaim_req req;

	/* Valid: correct version, non-empty NUL-terminated label. */
	memset(&req, 0, sizeof(req));
	req.version = SWITCHBOARD_RECLAIM_VERSION;
	(void)strlcpy(req.label, "system.Foo", sizeof(req.label));
	ATF_CHECK_MSG(reclaim_req_valid(&req), "a well-formed request must pass");

	/* Wrong version. */
	req.version = SWITCHBOARD_RECLAIM_VERSION + 1;
	ATF_CHECK_MSG(!reclaim_req_valid(&req),
	    "a version mismatch must be rejected");
	req.version = SWITCHBOARD_RECLAIM_VERSION;

	/* Empty label: nothing to reclaim. */
	req.label[0] = '\0';
	ATF_CHECK_MSG(!reclaim_req_valid(&req),
	    "an empty label must be rejected");

	/* Label with no NUL anywhere in the field. */
	memset(req.label, 'A', sizeof(req.label));
	ATF_CHECK_MSG(!reclaim_req_valid(&req),
	    "a non-NUL-terminated label must be rejected");

	/* Longest label that still leaves room for the NUL. */
	memset(req.label, 'A', sizeof(req.label) - 1);
	req.label[sizeof(req.label) - 1] = '\0';
	ATF_CHECK_MSG(reclaim_req_valid(&req),
	    "a field-1 length label with a terminating NUL must pass");
}

/*
 * Mock reclaim action: record the label it was handed and return a fixed
 * provider count so the reply can be asserted.
 */
struct mock_action_state {
	unsigned	calls;
	char		last_label[SWITCHBOARD_RECLAIM_LABEL_MAX];
	unsigned	ret;
};

static unsigned
mock_action(const char *label, void *arg)
{
	struct mock_action_state *st = arg;

	st->calls++;
	(void)strlcpy(st->last_label, label, sizeof(st->last_label));
	return (st->ret);
}

/*
 * Drive reclaim_bridge_serve() over one end of a socketpair, having written a
 * request on the other end first; read back the reply.  Returns the serve()
 * return value; fills *reply.
 */
static int
run_serve(const struct switchboard_reclaim_req *req, bool authorized,
    reclaim_bridge_action action, void *arg,
    struct switchboard_reclaim_reply *reply)
{
	int sv[2];
	ssize_t r;
	int rc;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));

	/* Client end (sv[1]) sends the request before serve reads it. */
	ATF_REQUIRE_EQ((ssize_t)sizeof(*req),
	    write(sv[1], req, sizeof(*req)));

	/* Server consumes sv[0], writes the reply, and closes sv[0]. */
	rc = reclaim_bridge_serve(sv[0], authorized, action, arg);

	memset(reply, 0, sizeof(*reply));
	r = read(sv[1], reply, sizeof(*reply));
	ATF_CHECK_EQ_MSG((ssize_t)sizeof(*reply), r,
	    "client must read a full reply (%zd bytes)", r);
	(void)close(sv[1]);
	return (rc);
}

/* ---- Guard 3a: authorized + valid → action runs, status 0, count relayed. */
ATF_TC_WITHOUT_HEAD(serve_authorized_valid_runs_action);
ATF_TC_BODY(serve_authorized_valid_runs_action, tc)
{
	struct switchboard_reclaim_req req;
	struct switchboard_reclaim_reply reply;
	struct mock_action_state st;

	memset(&req, 0, sizeof(req));
	req.version = SWITCHBOARD_RECLAIM_VERSION;
	(void)strlcpy(req.label, "system.Widget", sizeof(req.label));

	memset(&st, 0, sizeof(st));
	st.ret = 4;

	ATF_CHECK_EQ(0, run_serve(&req, true, mock_action, &st, &reply));
	ATF_CHECK_EQ_MSG(0, reply.status, "authorized+valid must return status 0");
	ATF_CHECK_EQ_MSG(4, reply.providers_notified,
	    "reply must relay the action's provider count");
	ATF_CHECK_EQ_MSG(1, st.calls, "the action must run exactly once");
	ATF_CHECK_STREQ_MSG("system.Widget", st.last_label,
	    "the action must receive the request label");
}

/* ---- Guard 3b: unauthorized peer → EPERM, action never runs. ---- */
ATF_TC_WITHOUT_HEAD(serve_unauthorized_is_eperm);
ATF_TC_BODY(serve_unauthorized_is_eperm, tc)
{
	struct switchboard_reclaim_req req;
	struct switchboard_reclaim_reply reply;
	struct mock_action_state st;

	memset(&req, 0, sizeof(req));
	req.version = SWITCHBOARD_RECLAIM_VERSION;
	(void)strlcpy(req.label, "system.Widget", sizeof(req.label));

	memset(&st, 0, sizeof(st));
	st.ret = 9;

	ATF_CHECK_EQ(0, run_serve(&req, false, mock_action, &st, &reply));
	ATF_CHECK_EQ_MSG((int32_t)EPERM, reply.status,
	    "an unauthorized (non-root) peer must be denied EPERM");
	ATF_CHECK_EQ_MSG(0, reply.providers_notified,
	    "a denied request must report zero providers");
	ATF_CHECK_EQ_MSG(0, st.calls,
	    "the action must NOT run for an unauthorized peer");
}

/* ---- Guard 3c: authorized but malformed → EINVAL, action never runs. ---- */
ATF_TC_WITHOUT_HEAD(serve_authorized_invalid_is_einval);
ATF_TC_BODY(serve_authorized_invalid_is_einval, tc)
{
	struct switchboard_reclaim_req req;
	struct switchboard_reclaim_reply reply;
	struct mock_action_state st;

	/* Authorized, but wrong version → invalid. */
	memset(&req, 0, sizeof(req));
	req.version = SWITCHBOARD_RECLAIM_VERSION + 1;
	(void)strlcpy(req.label, "system.Widget", sizeof(req.label));

	memset(&st, 0, sizeof(st));
	st.ret = 3;

	ATF_CHECK_EQ(0, run_serve(&req, true, mock_action, &st, &reply));
	ATF_CHECK_EQ_MSG((int32_t)EINVAL, reply.status,
	    "a malformed request must be rejected EINVAL");
	ATF_CHECK_EQ_MSG(0, st.calls,
	    "the action must NOT run for a malformed request");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, peer_authorized_root_only);
	ATF_TP_ADD_TC(tp, req_validation_edges);
	ATF_TP_ADD_TC(tp, serve_authorized_valid_runs_action);
	ATF_TP_ADD_TC(tp, serve_unauthorized_is_eperm);
	ATF_TP_ADD_TC(tp, serve_authorized_invalid_is_einval);

	return (atf_no_error());
}
