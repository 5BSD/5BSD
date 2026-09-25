/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Plane tests for BSDPower(8)'s per-session request handler.
 *
 * A real capability channel is created through /dev/mac_capability; BSDPower's
 * per-session worker (bsdpower_test_serve_session) runs the provider end in a
 * forked child while the test drives the client end with a libservice session,
 * exactly as it would over a held system.Power channel.
 *
 * The cases exercise the DAEMON's decision logic -- protocol validation
 * (magic, ABI version, framing), the per-label suspend policy, and opcode
 * dispatch -- without ever touching /dev/acpi: the worker is started with no
 * ACPI descriptor, so a SUSPEND that policy lets through is answered ENODEV
 * (the last check before the ioctl), which distinguishes "policy allowed it"
 * from "policy refused it" (EPERM) and from a bad state number (EINVAL)
 * without ever putting the test machine to sleep.
 *
 * Two cases need no plane at all (worker argument validation and the
 * supported-state sysctl parser) and run anywhere; the rest skip when
 * /dev/mac_capability cannot be opened.
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "powercmp_protocol.h"
#include "config.h"
#include "BSDPower_test.h"

#define	TEST_LABEL	"org.test.bsdpower.client"
#define	OTHER_LABEL	"org.test.bsdpower.other"

/* A mask a test can recognise on the wire: S3 and S5 but not S4. */
#define	TEST_STATES	(((uint32_t)1 << 3) | ((uint32_t)1 << 5))

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
 * Build the per-session policy.  `allow` sets the default for every label;
 * `grant` (optional) additionally lists one label as explicitly permitted so a
 * case can show the decision is keyed by the caller's label, not the default.
 */
static void
make_config(struct powercmp_config *config, bool allow, const char *grant)
{

	powercmp_config_defaults(config);
	config->default_suspend = allow;
	if (grant != NULL) {
		strlcpy(config->clients[0].label, grant,
		    sizeof(config->clients[0].label));
		config->clients[0].may_suspend = true;
		config->nclients = 1;
	}
}

/*
 * Fork the worker serving `label` with `config`.  The child never holds an
 * ACPI descriptor (bsdpower_test_set_acpi_fd(-1)) so no case can suspend the
 * host; the supported-state mask is pinned to TEST_STATES.
 */
static void
fixture_create_as(struct fixture *fixture, const char *label,
    const struct powercmp_config *config, uint32_t states)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		bsdpower_test_set_acpi_fd(-1);
		bsdpower_test_set_states(states);
		_exit(bsdpower_test_serve_session(provider, label, config));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_create(struct fixture *fixture, const struct powercmp_config *config)
{

	fixture_create_as(fixture, TEST_LABEL, config, TEST_STATES);
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
}

/*
 * Send `len` raw bytes (and optionally one descriptor) as a request and
 * collect the reply.  On a successful transport returns 0 and fills *reply
 * (and *reply_body when the reply carries one); returns -1 if the transport
 * itself fails (the provider tore the session down).
 */
static int
call_raw(struct fixture *fixture, const void *data, size_t len, int fd,
    struct powercmp_msg *reply, struct powercmp_body *reply_body)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t rbuf[POWERCMP_MAX_MESSAGE];
	int fdslot[1];

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = __DECONST(void *, data);
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

/*
 * Issue one well-formed request: a header (magic, ABI version, opcode) plus an
 * optional powercmp_body.  hdr_len lets a caller send a deliberately short or
 * long header when body == NULL.
 */
static int
call(struct fixture *fixture, uint16_t opcode, const struct powercmp_body *body,
    size_t hdr_len, int fd, struct powercmp_msg *reply,
    struct powercmp_body *reply_body)
{
	uint8_t obuf[2 * POWERCMP_MAX_MESSAGE];
	struct powercmp_msg req;
	size_t len;

	ATF_REQUIRE(hdr_len <= sizeof(obuf));
	memset(obuf, 0, sizeof(obuf));
	memset(&req, 0, sizeof(req));
	req.magic = POWERCMP_MAGIC;
	req.version = POWERCMP_ABI_VERSION;
	req.opcode = opcode;
	memcpy(obuf, &req, sizeof(req));
	len = hdr_len;
	if (body != NULL) {
		memcpy(obuf + sizeof(req), body, sizeof(*body));
		len = sizeof(req) + sizeof(*body);
	}
	return (call_raw(fixture, obuf, len, fd, reply, reply_body));
}

/* -------- plane-free: worker argument validation + sysctl parser -------- */

ATF_TC_WITHOUT_HEAD(serve_session_rejects_bad_arguments);
ATF_TC_BODY(serve_session_rejects_bad_arguments, tc)
{
	struct powercmp_config config;

	powercmp_config_defaults(&config);
	errno = 0;
	ATF_CHECK_EQ(-1, bsdpower_test_serve_session(-1, TEST_LABEL, &config));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, bsdpower_test_serve_session(0, NULL, &config));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, bsdpower_test_serve_session(0, "", &config));
	ATF_CHECK_EQ(EINVAL, errno);
	errno = 0;
	ATF_CHECK_EQ(-1, bsdpower_test_serve_session(0, TEST_LABEL, NULL));
	ATF_CHECK_EQ(EINVAL, errno);
}

/*
 * The mask BSDPower caches at startup must agree with an independent parse of
 * hw.acpi.supported_sleep_state ("S3 S4 S5" -> bits 3,4,5); a host without
 * ACPI sleep support (or without the OID) yields 0.
 */
ATF_TC_WITHOUT_HEAD(supported_states_matches_sysctl);
ATF_TC_BODY(supported_states_matches_sysctl, tc)
{
	char buf[64];
	size_t len = sizeof(buf) - 1;
	uint32_t expected = 0, mask;
	const char *p;

	if (sysctlbyname("hw.acpi.supported_sleep_state", buf, &len, NULL, 0)
	    == 0) {
		buf[len] = '\0';
		for (p = buf; *p != '\0'; p++)
			if ((*p == 'S' || *p == 's') && p[1] >= '1' && p[1] <= '5')
				expected |= (uint32_t)1 << (p[1] - '0');
	}
	mask = bsdpower_test_supported_states();
	ATF_CHECK_EQ_MSG(expected, mask, "expected 0x%x got 0x%x", expected,
	    mask);
	/* Only S1..S5 can ever be reported. */
	ATF_CHECK_EQ(0, mask & ~(uint32_t)0x3e);
}

/* -------- positive: HELLO + STATES -------- */

ATF_TC(hello_ok);
ATF_TC_HEAD(hello_ok, tc) { atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(hello_ok, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;

	require_plane();
	make_config(&config, false, NULL);
	fixture_create(&fixture, &config);
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_HELLO, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(POWERCMP_MAGIC, reply.magic);
	ATF_CHECK_EQ(POWERCMP_ABI_VERSION, reply.version);
	ATF_CHECK_EQ(POWERCMP_OP_HELLO, reply.opcode);
	fixture_destroy(&fixture);
}

ATF_TC(states_reports_cached_mask);
ATF_TC_HEAD(states_reports_cached_mask, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(states_reports_cached_mask, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, false, NULL);	/* STATES is never gated */
	fixture_create(&fixture, &config);
	memset(&body, 0xff, sizeof(body));
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_STATES, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, &body));
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(POWERCMP_OP_STATES, reply.opcode);
	ATF_CHECK_EQ(TEST_STATES, body.supported);
	ATF_CHECK_EQ(0, body.state);
	ATF_CHECK_EQ(0, body.reserved[0]);
	ATF_CHECK_EQ(0, body.reserved[1]);
	fixture_destroy(&fixture);
}

ATF_TC(states_reports_zero_without_acpi);
ATF_TC_HEAD(states_reports_zero_without_acpi, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(states_reports_zero_without_acpi, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, false, NULL);
	fixture_create_as(&fixture, TEST_LABEL, &config, 0);
	memset(&body, 0xff, sizeof(body));
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_STATES, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, &body));
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(0, body.supported);
	fixture_destroy(&fixture);
}

/* -------- policy: deny is the default, allow lets it reach the device ------ */

ATF_TC(suspend_denied_by_default_policy);
ATF_TC_HEAD(suspend_denied_by_default_policy, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_denied_by_default_policy, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, false, NULL);	/* default-deny */
	fixture_create(&fixture, &config);
	memset(&body, 0, sizeof(body));
	body.state = 3;				/* a valid S3; never applied */
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0, -1,
	    &reply, NULL));
	ATF_CHECK_EQ(EPERM, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_allowed_reaches_device);
ATF_TC_HEAD(suspend_allowed_reaches_device, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_allowed_reaches_device, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, true, NULL);	/* allow; no /dev/acpi held */
	fixture_create(&fixture, &config);
	memset(&body, 0, sizeof(body));
	body.state = 3;
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0, -1,
	    &reply, NULL));
	/*
	 * Policy let the request through to the device step; with no ACPI
	 * descriptor the daemon answers ENODEV, which proves the request was NOT
	 * stopped by policy (that would be EPERM) and the host never slept.
	 */
	ATF_CHECK_EQ(ENODEV, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_policy_is_per_label);
ATF_TC_HEAD(suspend_policy_is_per_label, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "a default-deny policy that grants one "
	    "label lets that label through (ENODEV: no device) and still refuses "
	    "another label (EPERM)");
}
ATF_TC_BODY(suspend_policy_is_per_label, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, false, TEST_LABEL);

	fixture_create_as(&fixture, TEST_LABEL, &config, TEST_STATES);
	memset(&body, 0, sizeof(body));
	body.state = 3;
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0, -1,
	    &reply, NULL));
	ATF_CHECK_EQ(ENODEV, -reply.status);
	fixture_destroy(&fixture);

	fixture_create_as(&fixture, OTHER_LABEL, &config, TEST_STATES);
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0, -1,
	    &reply, NULL));
	ATF_CHECK_EQ(EPERM, -reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_bad_state_is_einval);
ATF_TC_HEAD(suspend_bad_state_is_einval, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_bad_state_is_einval, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;
	static const uint32_t bad[] = { 0, 6, 32, UINT32_MAX };
	size_t i;

	require_plane();
	make_config(&config, true, NULL);	/* allow, so only the range check can fail */
	fixture_create(&fixture, &config);
	for (i = 0; i < nitems(bad); i++) {
		memset(&body, 0, sizeof(body));
		body.state = bad[i];
		ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0,
		    -1, &reply, NULL));
		ATF_CHECK_EQ_MSG(EINVAL, -reply.status, "state %u: status %d",
		    bad[i], reply.status);
	}
	/* The range check is not terminal: the session still answers. */
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_HELLO, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(0, reply.status);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_denied_before_state_check);
ATF_TC_HEAD(suspend_denied_before_state_check, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "a refused label learns nothing about "
	    "argument validity: an out-of-range state is still EPERM under deny");
}
ATF_TC_BODY(suspend_denied_before_state_check, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	struct powercmp_body body;

	require_plane();
	make_config(&config, false, NULL);
	fixture_create(&fixture, &config);
	memset(&body, 0, sizeof(body));
	body.state = 99;
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, &body, 0, -1,
	    &reply, NULL));
	ATF_CHECK_EQ(EPERM, -reply.status);
	fixture_destroy(&fixture);
}

/* -------- adversarial / edge: malformed framing -------- */

/*
 * A top-level protocol violation (bad magic or ABI version, unknown opcode, a
 * header truncated below sizeof(powercmp_msg), a message longer than header +
 * body, or an attached SCM descriptor) is rejected AND terminates the session
 * (the handler sets session->error).  The reply, if it arrives, is EPROTO; but
 * the tear-down races the flush, so the client may instead observe the
 * connection closed (call_raw() == -1).  Either is a correct rejection -- the
 * request must never be honoured.
 */
static void
check_rejected_raw(const void *data, size_t len, int fd)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;
	int rc;

	require_plane();
	make_config(&config, true, NULL);	/* allow, so only framing can fail */
	fixture_create(&fixture, &config);
	rc = call_raw(&fixture, data, len, fd, &reply, NULL);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, -reply.status);
	/* rc == -1: the session was torn down -- also a rejection. */
	fixture_destroy(&fixture);
}

static void
check_rejected(uint16_t opcode, size_t hdr_len, int fd)
{
	uint8_t obuf[2 * POWERCMP_MAX_MESSAGE];
	struct powercmp_msg req;

	ATF_REQUIRE(hdr_len <= sizeof(obuf));
	memset(obuf, 0, sizeof(obuf));
	memset(&req, 0, sizeof(req));
	req.magic = POWERCMP_MAGIC;
	req.version = POWERCMP_ABI_VERSION;
	req.opcode = opcode;
	memcpy(obuf, &req, sizeof(req));
	check_rejected_raw(obuf, hdr_len, fd);
}

ATF_TC(hello_wrong_abi_version_is_rejected);
ATF_TC_HEAD(hello_wrong_abi_version_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(hello_wrong_abi_version_is_rejected, tc)
{
	struct powercmp_msg req;

	/* Version negotiation is strict: only POWERCMP_ABI_VERSION is spoken. */
	memset(&req, 0, sizeof(req));
	req.magic = POWERCMP_MAGIC;
	req.version = POWERCMP_ABI_VERSION + 1;
	req.opcode = POWERCMP_OP_HELLO;
	check_rejected_raw(&req, sizeof(req), -1);
}

ATF_TC(hello_wrong_magic_is_rejected);
ATF_TC_HEAD(hello_wrong_magic_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(hello_wrong_magic_is_rejected, tc)
{
	struct powercmp_msg req;

	memset(&req, 0, sizeof(req));
	req.magic = POWERCMP_MAGIC ^ 0xffU;
	req.version = POWERCMP_ABI_VERSION;
	req.opcode = POWERCMP_OP_HELLO;
	check_rejected_raw(&req, sizeof(req), -1);
}

ATF_TC(unknown_opcode_is_rejected);
ATF_TC_HEAD(unknown_opcode_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(unknown_opcode_is_rejected, tc)
{

	check_rejected(0x7fff, sizeof(struct powercmp_msg), -1);
}

ATF_TC(zero_opcode_is_rejected);
ATF_TC_HEAD(zero_opcode_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(zero_opcode_is_rejected, tc)
{

	/* Opcodes start at 1; an all-zero opcode field is not HELLO. */
	check_rejected(0, sizeof(struct powercmp_msg), -1);
}

ATF_TC(short_message_is_rejected);
ATF_TC_HEAD(short_message_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(short_message_is_rejected, tc)
{

	/* A header truncated below sizeof(powercmp_msg) is a framing error. */
	check_rejected(POWERCMP_OP_STATES, sizeof(struct powercmp_msg) - 4, -1);
}

ATF_TC(oversized_message_is_rejected);
ATF_TC_HEAD(oversized_message_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(oversized_message_is_rejected, tc)
{

	/* Longer than header + body: neither legal frame length. */
	check_rejected(POWERCMP_OP_STATES, POWERCMP_MAX_MESSAGE + 8, -1);
}

ATF_TC(partial_body_is_rejected);
ATF_TC_HEAD(partial_body_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(partial_body_is_rejected, tc)
{

	/* Header plus a torn body (between the two legal lengths). */
	check_rejected(POWERCMP_OP_SUSPEND,
	    sizeof(struct powercmp_msg) + sizeof(struct powercmp_body) / 2, -1);
}

ATF_TC(suspend_missing_body_is_eproto);
ATF_TC_HEAD(suspend_missing_body_is_eproto, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_missing_body_is_eproto, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	struct powercmp_msg reply;

	require_plane();
	make_config(&config, true, NULL);	/* allow, so only framing can fail */
	fixture_create(&fixture, &config);
	/* SUSPEND with a bare header and no powercmp_body -> EPROTO. */
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_SUSPEND, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(EPROTO, -reply.status);
	/* Opcode-level framing is not terminal: the session still answers. */
	ATF_REQUIRE_EQ(0, call(&fixture, POWERCMP_OP_HELLO, NULL,
	    sizeof(struct powercmp_msg), -1, &reply, NULL));
	ATF_CHECK_EQ(0, reply.status);
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
	check_rejected(POWERCMP_OP_HELLO, sizeof(struct powercmp_msg), null);
	close(null);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, serve_session_rejects_bad_arguments);
	ATF_TP_ADD_TC(tp, supported_states_matches_sysctl);
	ATF_TP_ADD_TC(tp, hello_ok);
	ATF_TP_ADD_TC(tp, states_reports_cached_mask);
	ATF_TP_ADD_TC(tp, states_reports_zero_without_acpi);
	ATF_TP_ADD_TC(tp, suspend_denied_by_default_policy);
	ATF_TP_ADD_TC(tp, suspend_allowed_reaches_device);
	ATF_TP_ADD_TC(tp, suspend_policy_is_per_label);
	ATF_TP_ADD_TC(tp, suspend_bad_state_is_einval);
	ATF_TP_ADD_TC(tp, suspend_denied_before_state_check);
	ATF_TP_ADD_TC(tp, hello_wrong_abi_version_is_rejected);
	ATF_TP_ADD_TC(tp, hello_wrong_magic_is_rejected);
	ATF_TP_ADD_TC(tp, unknown_opcode_is_rejected);
	ATF_TP_ADD_TC(tp, zero_opcode_is_rejected);
	ATF_TP_ADD_TC(tp, short_message_is_rejected);
	ATF_TP_ADD_TC(tp, oversized_message_is_rejected);
	ATF_TP_ADD_TC(tp, partial_body_is_rejected);
	ATF_TP_ADD_TC(tp, suspend_missing_body_is_eproto);
	ATF_TP_ADD_TC(tp, rejects_attached_fd);

	return (atf_no_error());
}
