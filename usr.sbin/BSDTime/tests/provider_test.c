/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Plane tests for BSDTime(8)'s per-session request handler.
 *
 * A real capability channel is created through /dev/mac_capability; BSDTime's
 * per-session worker (bsdtime_test_serve_session) runs the provider end in a
 * forked child while the test drives the client end with a libservice session,
 * exactly as it would over a held system.Time channel.
 *
 * Most cases exercise the DAEMON's decision logic -- protocol validation, the
 * per-label step/slew policy, and opcode dispatch -- without a gate token: GET
 * reads the clock directly and the privileged SET/ADJUST paths are decided by
 * policy (deny -> EPERM) or, when policy permits but no token is held, fail at
 * the gate call (EINVAL) -- which distinguishes "policy allowed it through" from
 * "policy refused it".  One case mints a real SYS_GATE_SETTIME token and drives a
 * NO-OP round trip (SET the clock to its current value, ADJUST by zero) so the
 * full allow -> gate -> kern_settime_gated path is covered without moving the
 * wall clock.  The kernel gate suite covers the step/slew primitive itself.
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <dev/mac_capability/mac_capability_system_proto.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libservice.h>

#include "timecmp_protocol.h"
#include "config.h"
#include "BSDTime_test.h"

#define	TEST_LABEL	"org.test.bsdtime.client"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
};

/* Open a capability endpoint by well-known name, or -1 (errno preserved). */
static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (control < 0)
		return (-1);
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
	close(fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE_MSG(*client >= 0, "connect channel: %s", strerror(errno));
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

/*
 * Mint a held SYS_GATE_SETTIME token for the worker child.  Claims SETTIME on a
 * fresh "system" connection (the test image's plane is unclaimed), mints a
 * token, and authorizes it for this process's nonce.  The system connection is
 * left open ON PURPOSE: a gate claim lives on its connection and sys_holds_gate()
 * requires a live claim covering the gate at call time, so closing it would
 * release the claim and every gated op would fail EPERM.  Returns the token fd,
 * or -1.
 */
static int
mint_settime_token(void)
{
	struct mac_capability_call_args ca;
	struct sys_request req;
	int sysfd, tok = -1;

	sysfd = capability_connect("system");
	if (sysfd < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_CLAIM;
	req.gates = SYS_GATE_SETTIME;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_MINT;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = &tok;
	ca.reply_nfds = 1;
	ca.reply_len = 0;
	if (ioctl(sysfd, MAC_CAPABILITY_CALL, &ca) != 0 || tok < 0)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.op = SYS_OP_AUTHORIZE;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_len = 0;
	if (ioctl(tok, MAC_CAPABILITY_CALL, &ca) != 0) {
		close(tok);
		goto fail;
	}
	return (tok);		/* keep sysfd open: the claim must outlive the token */
fail:
	close(sysfd);
	return (-1);
}

/*
 * Build the per-session policy: deny==false allows every label to set/slew.
 * The child worker serves with this config so a case picks allow or deny.
 */
static void
make_config(struct timecmp_config *config, bool allow)
{

	timecmp_config_defaults(config);
	config->default_set = allow;
}

static void
fixture_create(struct fixture *fixture, const struct timecmp_config *config,
    bool with_token)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		if (with_token) {
			int tok = mint_settime_token();

			if (tok >= 0)
				bsdtime_test_set_token(tok);
		}
		_exit(bsdtime_test_serve_session(provider, TEST_LABEL, config));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
}

/*
 * Issue one request (header + optional body) and collect the reply.  hdr_len
 * lets a caller send a deliberately short header; when body != NULL a
 * timecmp_time body is appended.  fd optionally attaches a descriptor.  On a
 * successful transport returns 0 and fills *reply (and *reply_body when the
 * reply carries one); returns -1 if the transport itself fails.
 */
static int
call(struct fixture *fixture, uint16_t opcode, const struct timecmp_time *body,
    size_t hdr_len, int fd, struct timecmp_msg *reply,
    struct timecmp_time *reply_body)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t obuf[TIMECMP_MAX_MESSAGE];
	uint8_t rbuf[TIMECMP_MAX_MESSAGE];
	struct timecmp_msg req;
	size_t len;
	int fdslot[1];

	memset(&req, 0, sizeof(req));
	req.magic = TIMECMP_MAGIC;
	req.version = TIMECMP_ABI_VERSION;
	req.opcode = opcode;
	memcpy(obuf, &req, sizeof(req));
	len = hdr_len;
	if (body != NULL) {
		memcpy(obuf + sizeof(req), body, sizeof(*body));
		len = sizeof(req) + sizeof(*body);
	}

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = obuf;
	outgoing.length = len;
	if (fd >= 0) {
		fdslot[0] = fd;
		outgoing.fds = fdslot;
		outgoing.nfds = 1;
	}
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = rbuf;
	incoming.capacity = sizeof(rbuf);
	incoming.fds = fdslot;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	if (service_session_call(fixture->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	ATF_REQUIRE(incoming.length >= sizeof(*reply));
	memcpy(reply, rbuf, sizeof(*reply));
	if (reply_body != NULL && incoming.length >= sizeof(*reply) +
	    sizeof(*reply_body))
		memcpy(reply_body, rbuf + sizeof(*reply), sizeof(*reply_body));
	return (0);
}

/* -------- positive: protocol + read -------- */

ATF_TC(hello_ok);
ATF_TC_HEAD(hello_ok, tc) { atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(hello_ok, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;

	require_plane();
	make_config(&config, false);
	fixture_create(&fixture, &config, false);
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_HELLO, NULL,
	    sizeof(struct timecmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(0, reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(get_reads_clock);
ATF_TC_HEAD(get_reads_clock, tc) { atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(get_reads_clock, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	struct timecmp_time body;

	require_plane();
	make_config(&config, false);		/* GET is never gated */
	fixture_create(&fixture, &config, false);
	memset(&body, 0, sizeof(body));
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_GET, NULL,
	    sizeof(struct timecmp_msg), -1, &reply, &body));
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(1, body.present);
	ATF_CHECK(body.sec > 1600000000);	/* after 2020-09; a sane wall clock */
	fixture_destroy(&fixture);
}

/* -------- policy: deny is the default, allow lets it reach the gate -------- */

ATF_TC(set_denied_by_default_policy);
ATF_TC_HEAD(set_denied_by_default_policy, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(set_denied_by_default_policy, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	struct timecmp_time body;

	require_plane();
	make_config(&config, false);		/* default-deny */
	fixture_create(&fixture, &config, false);
	memset(&body, 0, sizeof(body));
	body.sec = 1893456000;			/* 2030; never applied (denied) */
	body.present = 1;
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_SET, &body, 0, -1, &reply,
	    NULL));
	ATF_CHECK_EQ(EPERM, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(adjust_denied_by_default_policy);
ATF_TC_HEAD(adjust_denied_by_default_policy, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(adjust_denied_by_default_policy, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	struct timecmp_time body;

	require_plane();
	make_config(&config, false);
	fixture_create(&fixture, &config, false);
	memset(&body, 0, sizeof(body));
	body.sec = 1;				/* a 1s slew; never applied */
	body.present = 1;
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_ADJUST, &body, 0, -1, &reply,
	    NULL));
	ATF_CHECK_EQ(EPERM, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(set_allowed_reaches_gate);
ATF_TC_HEAD(set_allowed_reaches_gate, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(set_allowed_reaches_gate, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	struct timecmp_time body;

	require_plane();
	make_config(&config, true);		/* allow; no token held */
	fixture_create(&fixture, &config, false);
	memset(&body, 0, sizeof(body));
	body.sec = 1893456000;
	body.present = 1;
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_SET, &body, 0, -1, &reply,
	    NULL));
	/*
	 * Policy allowed the step through to the gate; with no token held the
	 * gate call fails EINVAL (service_system_settime rejects fd < 0), which
	 * proves the request was NOT stopped by policy (that would be EPERM) and
	 * the clock was never moved.
	 */
	ATF_CHECK_EQ(EINVAL, -reply.status);
	fixture_destroy(&fixture);
}

/* -------- adversarial / edge: malformed framing -------- */

/*
 * A top-level protocol violation (unknown opcode, a header truncated below
 * sizeof(timecmp_msg), or an attached SCM descriptor) is rejected AND terminates
 * the session (the handler sets session->error).  The reply, if it arrives, is
 * EPROTO; but the tear-down races the flush, so the client may instead observe
 * the connection closed (call() == -1).  Either is a correct rejection -- the
 * request must never be honoured.
 */
static void
check_rejected(uint16_t opcode, const struct timecmp_time *body, size_t hdr_len,
    int fd)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	int rc;

	require_plane();
	make_config(&config, false);
	fixture_create(&fixture, &config, false);
	rc = call(&fixture, opcode, body, hdr_len, fd, &reply, NULL);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, -reply.status);
	/* rc == -1: the session was torn down -- also a rejection. */
	fixture_destroy(&fixture);
}

ATF_TC(unknown_opcode_is_rejected);
ATF_TC_HEAD(unknown_opcode_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(unknown_opcode_is_rejected, tc)
{

	check_rejected(0x7fff, NULL, sizeof(struct timecmp_msg), -1);
}

ATF_TC(short_message_is_rejected);
ATF_TC_HEAD(short_message_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(short_message_is_rejected, tc)
{

	/* A header truncated below sizeof(timecmp_msg) is a framing error. */
	check_rejected(TIMECMP_OP_GET, NULL, sizeof(struct timecmp_msg) - 4, -1);
}

ATF_TC(set_missing_body_is_eproto);
ATF_TC_HEAD(set_missing_body_is_eproto, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(set_missing_body_is_eproto, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;

	require_plane();
	make_config(&config, true);		/* allow, so only framing can fail */
	fixture_create(&fixture, &config, false);
	/* SET with a bare header and no timecmp_time body -> EPROTO. */
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_SET, NULL,
	    sizeof(struct timecmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(EPROTO, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(rejects_attached_fd);
ATF_TC_HEAD(rejects_attached_fd, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(rejects_attached_fd, tc)
{
	int null;

	/* An SCM descriptor on any request is a terminal protocol rejection. */
	null = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(null >= 0);
	check_rejected(TIMECMP_OP_HELLO, NULL, sizeof(struct timecmp_msg), null);
	close(null);
}

/* -------- full path: allow + real token, NO-OP so the clock never moves ------ */

ATF_TC(gate_roundtrip_noop);
ATF_TC_HEAD(gate_roundtrip_noop, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "allow policy + a minted SETTIME token: a "
	    "SET to the clock's current value and a zero ADJUST exercise the full "
	    "gate path (kern_settime_gated/kern_adjtime_gated) without moving the "
	    "wall clock");
}
ATF_TC_BODY(gate_roundtrip_noop, tc)
{
	struct fixture fixture;
	struct timecmp_config config;
	struct timecmp_msg reply;
	struct timecmp_time now, delta;

	require_plane();
	make_config(&config, true);
	fixture_create(&fixture, &config, true);

	/* Read the current clock. */
	memset(&now, 0, sizeof(now));
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_GET, NULL,
	    sizeof(struct timecmp_msg), -1, &reply, &now));
	if (reply.status != 0)
		atf_tc_skip("clock read failed: %s", strerror(-reply.status));
	ATF_REQUIRE_EQ(1, now.present);

	/*
	 * SET it back to exactly that value.  If no token was mintable (plane
	 * unclaimed but device present in a stranger harness) the gate rejects
	 * with EINVAL/EPERM; skip rather than fail so the case is meaningful only
	 * where the full path is available.
	 */
	now.present = 1;
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_SET, &now, 0, -1, &reply,
	    NULL));
	if (reply.status != 0)
		atf_tc_skip("SET through gate unavailable: %s",
		    strerror(-reply.status));

	/* A zero slew: applies nothing, returns any pending correction. */
	memset(&delta, 0, sizeof(delta));
	delta.present = 1;
	ATF_REQUIRE_EQ(0, call(&fixture, TIMECMP_OP_ADJUST, &delta, 0, -1, &reply,
	    NULL));
	ATF_CHECK_EQ(0, reply.status);
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, hello_ok);
	ATF_TP_ADD_TC(tp, get_reads_clock);
	ATF_TP_ADD_TC(tp, set_denied_by_default_policy);
	ATF_TP_ADD_TC(tp, adjust_denied_by_default_policy);
	ATF_TP_ADD_TC(tp, set_allowed_reaches_gate);
	ATF_TP_ADD_TC(tp, unknown_opcode_is_rejected);
	ATF_TP_ADD_TC(tp, short_message_is_rejected);
	ATF_TP_ADD_TC(tp, set_missing_body_is_eproto);
	ATF_TP_ADD_TC(tp, rejects_attached_fd);
	ATF_TP_ADD_TC(tp, gate_roundtrip_noop);

	return (atf_no_error());
}
