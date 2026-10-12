/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Plane tests for BSDPower(8)'s per-session request handler.
 *
 * A real capability channel is created through /dev/mac_capability; BSDPower's
 * per-session FIDL server (bsdpower_test_serve_session) runs the provider end
 * in a forked child while the test drives the client end with the real
 * libpowercmp client (bsd.power.v1 bindings), exactly as it would over a held
 * system.Power channel.  Adversarial cases hand-build FIDL frames on a raw
 * libservice session so the provider's own validation is what rejects them.
 *
 * The cases exercise the DAEMON's decision logic -- negotiation, FIDL framing
 * and decoding, the per-label suspend policy, and method dispatch -- without
 * ever touching /dev/acpi: the worker is started with no
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

#include "powercmp.h"
#include "config.h"
#include "BSDPower_test.h"

#define	TEST_LABEL	"org.test.bsdpower.client"
#define	OTHER_LABEL	"org.test.bsdpower.other"

/* A mask a test can recognise on the wire: S3 and S5 but not S4. */
#define	TEST_STATES	(((uint32_t)1 << 3) | ((uint32_t)1 << 5))

struct fixture {
	struct powercmp_client	*client;
	struct service_session	*session;	/* raw-frame cases only */
	pid_t			 child;
};

/* FIDL v2 transactional message header. */
struct wire_header {
	uint32_t txid;
	uint8_t flags[3], magic;
	uint64_t ordinal;
};
_Static_assert(sizeof(struct wire_header) == 16, "FIDL header");
#define ORD_INFO	UINT64_C(0x3f885bd44685314f)
#define ORD_STATES	UINT64_C(0x0f11f6de81f94c47)
#define ORD_SUSPEND	UINT64_C(0x77e5c25be901e930)

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
    const struct powercmp_config *config, uint32_t states, bool raw)
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
	if (raw)
		ATF_REQUIRE_EQ(0, service_session_create(client,
		    &fixture->session));
	else
		ATF_REQUIRE_EQ(0, powercmp_client_create(client,
		    &fixture->client));
}

static void
fixture_create(struct fixture *fixture, const struct powercmp_config *config)
{

	fixture_create_as(fixture, TEST_LABEL, config, TEST_STATES, false);
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	if (fixture->client != NULL)
		powercmp_client_close(fixture->client);
	if (fixture->session != NULL)
		service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

/*
 * Send `len` raw bytes (and optionally one descriptor) as a request and
 * collect the reply bytes.  Returns 0 and the reply length, or -1 if the
 * transport fails (the provider closed the session).
 */
static int
call_raw(struct fixture *fixture, const void *data, size_t len, int fd,
    uint8_t *reply, size_t *reply_len)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
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
	incoming.data = reply;
	incoming.capacity = 64;
	incoming.fds = fdslot;
	incoming.fd_capacity = 1;
	options.timeout_ms = 5000;
	if (service_session_call(fixture->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	ATF_REQUIRE_EQ(0, incoming.nfds);
	*reply_len = incoming.length;
	return (0);
}

/* A raw FIDL request: header plus `body` bytes. */
static int
call_frame(struct fixture *fixture, uint32_t txid, uint64_t ordinal,
    const void *body, size_t body_len, uint8_t *reply, size_t *reply_len)
{
	uint8_t frame[64];
	struct wire_header header = { txid, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(sizeof(header) + body_len <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	if (body_len != 0)
		memcpy(frame + sizeof(header), body, body_len);
	return (call_raw(fixture, frame, sizeof(header) + body_len, -1, reply,
	    reply_len));
}

static void
negotiate_raw(struct fixture *fixture)
{
	uint8_t reply[64];
	size_t length;
	uint32_t version;

	ATF_REQUIRE_EQ(0, call_frame(fixture, 1, ORD_INFO, NULL, 0, reply,
	    &length));
	ATF_REQUIRE_EQ(24, length);
	memcpy(&version, reply + 16, sizeof(version));
	ATF_REQUIRE_EQ(POWERCMP_WIRE_VERSION, version);
}

/*
 * Raw Suspend, bypassing the client's own range check.  Returns the
 * application errno carried by the result union (0 for success).
 */
static int
suspend_raw(struct fixture *fixture, uint32_t txid, uint32_t state)
{
	uint8_t body[8] = { 0 }, reply[64];
	uint64_t tag;
	uint32_t value;
	size_t length;

	memcpy(body, &state, sizeof(state));
	ATF_REQUIRE_EQ(0, call_frame(fixture, txid, ORD_SUSPEND, body,
	    sizeof(body), reply, &length));
	ATF_REQUIRE_EQ(32, length);
	memcpy(&tag, reply + 16, sizeof(tag));
	memcpy(&value, reply + 24, sizeof(value));
	return (tag == 2 ? (int)value : 0);
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

/* -------- positive: States -------- */

ATF_TC(states_reports_cached_mask);
ATF_TC_HEAD(states_reports_cached_mask, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(states_reports_cached_mask, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	uint32_t supported = UINT32_MAX;

	require_plane();
	make_config(&config, false, NULL);	/* States is never gated */
	fixture_create(&fixture, &config);
	ATF_REQUIRE_EQ(0, powercmp_states(fixture.client, &supported));
	ATF_CHECK_EQ(TEST_STATES, supported);
	fixture_destroy(&fixture);
}

ATF_TC(states_reports_zero_without_acpi);
ATF_TC_HEAD(states_reports_zero_without_acpi, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(states_reports_zero_without_acpi, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	uint32_t supported = UINT32_MAX;

	require_plane();
	make_config(&config, false, NULL);
	fixture_create_as(&fixture, TEST_LABEL, &config, 0, false);
	ATF_REQUIRE_EQ(0, powercmp_states(fixture.client, &supported));
	ATF_CHECK_EQ(0, supported);
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
	uint32_t count;

	require_plane();
	make_config(&config, false, NULL);	/* default-deny */
	fixture_create(&fixture, &config);
	/* A valid S3; never applied. */
	ATF_CHECK_ERRNO(EPERM, powercmp_suspend(fixture.client, 3) == -1);
	ATF_CHECK_ERRNO(EPERM, powercmp_inhibit(fixture.client) == -1);
	/* Policy refusals keep the session usable. */
	ATF_CHECK_EQ(0, powercmp_inhibitors(fixture.client, &count));
	ATF_CHECK_EQ(0, count);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_allowed_reaches_device);
ATF_TC_HEAD(suspend_allowed_reaches_device, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_allowed_reaches_device, tc)
{
	struct fixture fixture;
	struct powercmp_config config;

	require_plane();
	make_config(&config, true, NULL);	/* allow; no /dev/acpi held */
	fixture_create(&fixture, &config);
	/*
	 * Policy let the request through to the device step; with no ACPI
	 * descriptor the daemon answers ENODEV, which proves the request was NOT
	 * stopped by policy (that would be EPERM) and the host never slept.
	 */
	ATF_CHECK_ERRNO(ENODEV, powercmp_suspend(fixture.client, 3) == -1);
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

	require_plane();
	make_config(&config, false, TEST_LABEL);

	fixture_create_as(&fixture, TEST_LABEL, &config, TEST_STATES, false);
	ATF_CHECK_ERRNO(ENODEV, powercmp_suspend(fixture.client, 3) == -1);
	fixture_destroy(&fixture);

	fixture_create_as(&fixture, OTHER_LABEL, &config, TEST_STATES, false);
	ATF_CHECK_ERRNO(EPERM, powercmp_suspend(fixture.client, 3) == -1);
	fixture_destroy(&fixture);
}

ATF_TC(suspend_bad_state_is_einval);
ATF_TC_HEAD(suspend_bad_state_is_einval, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_bad_state_is_einval, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	static const uint32_t bad[] = { 0, 6, 32, UINT32_MAX };
	uint8_t reply[64];
	size_t i, length;

	require_plane();
	make_config(&config, true, NULL);	/* allow, so only the range check can fail */
	fixture_create_as(&fixture, TEST_LABEL, &config, TEST_STATES, true);
	negotiate_raw(&fixture);
	/* The provider checks the range itself; the client never sends these. */
	for (i = 0; i < nitems(bad); i++)
		ATF_CHECK_EQ_MSG(EINVAL, suspend_raw(&fixture, 2 + i, bad[i]),
		    "state %u", bad[i]);
	/* The range check is not terminal: the session still answers. */
	ATF_REQUIRE_EQ(0, call_frame(&fixture, 9, ORD_STATES, NULL, 0, reply,
	    &length));
	ATF_CHECK_EQ(24, length);
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

	require_plane();
	make_config(&config, false, NULL);
	fixture_create_as(&fixture, TEST_LABEL, &config, TEST_STATES, true);
	negotiate_raw(&fixture);
	ATF_CHECK_EQ(EPERM, suspend_raw(&fixture, 2, 99));
	fixture_destroy(&fixture);
}

ATF_TC(client_rejects_bad_state_locally);
ATF_TC_HEAD(client_rejects_bad_state_locally, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(client_rejects_bad_state_locally, tc)
{
	struct fixture fixture;
	struct powercmp_config config;
	uint32_t supported;

	require_plane();
	make_config(&config, true, NULL);
	fixture_create(&fixture, &config);
	ATF_CHECK_ERRNO(EINVAL, powercmp_suspend(fixture.client, 0) == -1);
	ATF_CHECK_ERRNO(EINVAL, powercmp_suspend(fixture.client, 6) == -1);
	ATF_CHECK_EQ(0, powercmp_states(fixture.client, &supported));
	fixture_destroy(&fixture);
}

/* -------- adversarial / edge: malformed framing -------- */

/*
 * A protocol violation -- a method before negotiation, an unknown strict
 * method, a truncated or oversized frame, a missing body, a pre-FIDL legacy
 * record or an attached descriptor -- closes the session without a reply:
 * the request is never honoured, and nothing later on the session is.
 */
static void
check_rejected_raw(bool negotiate, const void *data, size_t len, int fd)
{
	struct fixture fixture;
	struct powercmp_config config;
	uint8_t reply[64];
	size_t length;

	require_plane();
	make_config(&config, true, NULL);	/* allow, so only framing can fail */
	fixture_create_as(&fixture, TEST_LABEL, &config, TEST_STATES, true);
	if (negotiate)
		negotiate_raw(&fixture);
	ATF_CHECK_EQ(-1, call_raw(&fixture, data, len, fd, reply, &length));
	ATF_CHECK(errno != ETIMEDOUT);
	ATF_CHECK_EQ(-1, call_frame(&fixture, 7, ORD_STATES, NULL, 0, reply,
	    &length));
	fixture_destroy(&fixture);
}

static void
check_rejected_frame(bool negotiate, uint64_t ordinal, size_t body_len,
    size_t total, int fd)
{
	uint8_t frame[64] = { 0 };
	struct wire_header header = { 5, { 2, 0, 0 }, 1, ordinal };

	ATF_REQUIRE(total <= sizeof(frame));
	memcpy(frame, &header, sizeof(header));
	(void)body_len;
	check_rejected_raw(negotiate, frame, total, fd);
}

ATF_TC(method_before_negotiation_is_rejected);
ATF_TC_HEAD(method_before_negotiation_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(method_before_negotiation_is_rejected, tc)
{
	check_rejected_frame(false, ORD_STATES, 0, 16, -1);
}

ATF_TC(unknown_method_is_rejected);
ATF_TC_HEAD(unknown_method_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(unknown_method_is_rejected, tc)
{
	check_rejected_frame(true, UINT64_C(0x7fff), 0, 16, -1);
}

ATF_TC(short_frame_is_rejected);
ATF_TC_HEAD(short_frame_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(short_frame_is_rejected, tc)
{
	/* A header truncated below 16 bytes is a framing error. */
	check_rejected_frame(true, ORD_STATES, 0, 8, -1);
}

ATF_TC(trailing_bytes_are_rejected);
ATF_TC_HEAD(trailing_bytes_are_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(trailing_bytes_are_rejected, tc)
{
	/* States takes no body; eight extra bytes are not a legal frame. */
	check_rejected_frame(true, ORD_STATES, 8, 24, -1);
}

ATF_TC(suspend_missing_body_is_rejected);
ATF_TC_HEAD(suspend_missing_body_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(suspend_missing_body_is_rejected, tc)
{
	check_rejected_frame(true, ORD_SUSPEND, 0, 16, -1);
}

ATF_TC(legacy_wire_is_rejected);
ATF_TC_HEAD(legacy_wire_is_rejected, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(legacy_wire_is_rejected, tc)
{
	struct powercmp_msg legacy;

	/* A pre-FIDL STATES record from an old client. */
	memset(&legacy, 0, sizeof(legacy));
	legacy.magic = POWERCMP_MAGIC;
	legacy.opcode = POWERCMP_OP_STATES;
	check_rejected_raw(false, &legacy, sizeof(legacy), -1);
}

ATF_TC(rejects_attached_fd);
ATF_TC_HEAD(rejects_attached_fd, tc)
{ atf_tc_set_md_var(tc, "require.user", "root"); }
ATF_TC_BODY(rejects_attached_fd, tc)
{
	int fds[2];
	char byte;

	/* A descriptor on any request is a terminal protocol rejection, and
	 * the provider closes its received copy. */
	ATF_REQUIRE_EQ(0, pipe(fds));
	check_rejected_frame(true, ORD_STATES, 0, 16, fds[1]);
	close(fds[1]);
	ATF_REQUIRE(fcntl(fds[0], F_SETFL, O_NONBLOCK) != -1);
	ATF_CHECK_EQ(0, read(fds[0], &byte, 1));
	close(fds[0]);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, serve_session_rejects_bad_arguments);
	ATF_TP_ADD_TC(tp, supported_states_matches_sysctl);
	ATF_TP_ADD_TC(tp, states_reports_cached_mask);
	ATF_TP_ADD_TC(tp, states_reports_zero_without_acpi);
	ATF_TP_ADD_TC(tp, suspend_denied_by_default_policy);
	ATF_TP_ADD_TC(tp, suspend_allowed_reaches_device);
	ATF_TP_ADD_TC(tp, suspend_policy_is_per_label);
	ATF_TP_ADD_TC(tp, suspend_bad_state_is_einval);
	ATF_TP_ADD_TC(tp, suspend_denied_before_state_check);
	ATF_TP_ADD_TC(tp, client_rejects_bad_state_locally);
	ATF_TP_ADD_TC(tp, method_before_negotiation_is_rejected);
	ATF_TP_ADD_TC(tp, unknown_method_is_rejected);
	ATF_TP_ADD_TC(tp, short_frame_is_rejected);
	ATF_TP_ADD_TC(tp, trailing_bytes_are_rejected);
	ATF_TP_ADD_TC(tp, suspend_missing_body_is_rejected);
	ATF_TP_ADD_TC(tp, legacy_wire_is_rejected);
	ATF_TP_ADD_TC(tp, rejects_attached_fd);

	return (atf_no_error());
}
