/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
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
#include <sysctlcmp_protocol.h>

#include "config.h"
#include "localsysctl_test.h"

#define	TEST_LABEL	"org.test.sysctl"

struct raw_fixture {
	struct service_session	*session;
	pid_t			 child;
};

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		atf_tc_skip("plane device /dev/mac_capability unavailable: %s",
		    strerror(errno));
	close(fd);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
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
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
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
 * A minimal default-deny policy: the default ACL permits reading exactly one
 * variable ("kern.ostype") and permits no writes.  The worker inherits a copy
 * of *config across the fork, so the per-label gating in handle_request() runs
 * on this exact policy.
 */
static void
make_config(struct sysctlcmp_config *config)
{

	memset(config, 0, sizeof(*config));
	strlcpy(config->default_acl.read[0], "kern.ostype",
	    sizeof(config->default_acl.read[0]));
	config->default_acl.nread = 1;
	config->default_acl.nwrite = 0;
	config->nclients = 0;
}

/*
 * Stand up a per-label provider worker bound to a caller-supplied client label
 * and policy, running the real serve/dispatch path over a plane channel.
 */
static void
raw_fixture_create(struct raw_fixture *fixture, const char *label,
    const struct sysctlcmp_config *config)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(sysctlcmp_test_serve(provider, label, config));
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
raw_fixture_destroy(struct raw_fixture *fixture, int expected_status)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

/*
 * Build and send one sysctlcmp request over the session.  HELLO carries only
 * the header; every other opcode carries a NUL-terminated name (and, for SET,
 * the new value bytes).  Returns the daemon's errno-style status (0 on success,
 * positive errno on a policy/kernel rejection).  On a value-bearing success the
 * reply value is copied through out/outlen (outlen carries the buffer size in,
 * the value length out).
 */
static int
sysctl_op(struct service_session *session, uint16_t opcode, const char *name,
    const void *newval, size_t newlen, void *out, size_t *outlen)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	uint8_t request[SYSCTLCMP_MAX_MESSAGE];
	uint8_t reply[SYSCTLCMP_MAX_MESSAGE];
	struct sysctlcmp_msg *msg;
	struct sysctlcmp_body *body;
	const struct sysctlcmp_msg *rmsg;
	const struct sysctlcmp_body *rbody;
	size_t name_len, length;

	memset(request, 0, sizeof(request));
	msg = (void *)request;
	msg->magic = SYSCTLCMP_MAGIC;
	msg->version = SYSCTLCMP_ABI_VERSION;
	msg->opcode = opcode;
	if (opcode == SYSCTLCMP_OP_HELLO) {
		length = sizeof(*msg);
	} else {
		name_len = strlen(name) + 1;
		ATF_REQUIRE(name_len <= SYSCTLCMP_MAX_NAME);
		ATF_REQUIRE(newlen <= SYSCTLCMP_MAX_VALUE);
		body = (void *)(msg + 1);
		body->name_length = (uint16_t)name_len;
		body->value_length = (uint32_t)newlen;
		memcpy(body + 1, name, name_len);
		if (newlen != 0)
			memcpy((uint8_t *)(body + 1) + name_len, newval, newlen);
		length = sizeof(*msg) + sizeof(*body) + name_len + newlen;
	}
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = length;
	memset(reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(session, &outgoing, &incoming,
	    &options));
	rmsg = (const void *)reply;
	if (rmsg->status != 0)
		return (-rmsg->status);
	if (out != NULL && outlen != NULL &&
	    incoming.length >= sizeof(*rmsg) + sizeof(*rbody)) {
		rbody = (const void *)(reply + sizeof(*rmsg));
		if (rbody->value_length <= *outlen)
			memcpy(out, (const uint8_t *)(rbody + 1) +
			    rbody->name_length, rbody->value_length);
		*outlen = rbody->value_length;
	}
	return (0);
}

/*
 * The dispatch handlers honour the per-label read/write policy: HELLO succeeds;
 * a GET of a policy-permitted read-only variable returns a value; a GET of a
 * non-permitted variable is refused EPERM before any sysctl(3); a SET is
 * refused EPERM because the policy grants no writes.
 */
ATF_TC(policy_gated_get_and_set);
ATF_TC_HEAD(policy_gated_get_and_set, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "GET/SET dispatch honours the per-label read/write policy");
}
ATF_TC_BODY(policy_gated_get_and_set, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t len;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* HELLO: header-only handshake succeeds. */
	ATF_CHECK_EQ(0, sysctl_op(fixture.session, SYSCTLCMP_OP_HELLO, NULL,
	    NULL, 0, NULL, NULL));

	/* GET of the one permitted variable returns a non-empty value. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.session, SYSCTLCMP_OP_GET,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len > 0);
	ATF_CHECK(len <= sizeof(value));
	ATF_CHECK_EQ('\0', value[len - 1]);

	/* GET of a non-permitted variable is denied by policy: EPERM. */
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.session, SYSCTLCMP_OP_GET,
	    "kern.osrelease", NULL, 0, value, &len));

	/* SET is denied by policy (no writes granted): EPERM, no write attempted. */
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.session, SYSCTLCMP_OP_SET,
	    "kern.ostype", "x", 1, NULL, NULL));

	raw_fixture_destroy(&fixture, 0);
}

/*
 * OIDFMT and DESCR on a permitted variable return introspection data: OIDFMT a
 * kind word plus a format string, DESCR a NUL-terminated description.  Both are
 * read-policy gated, so a non-permitted variable is refused EPERM.
 */
ATF_TC(introspection_is_gated);
ATF_TC_HEAD(introspection_is_gated, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "OIDFMT and DESCR return data for permitted names and deny others");
}
ATF_TC_BODY(introspection_is_gated, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	uint8_t value[SYSCTLCMP_MAX_VALUE];
	size_t len;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* OIDFMT: at least the leading uint32_t kind word is present. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.session, SYSCTLCMP_OP_OIDFMT,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len >= sizeof(uint32_t));

	/* DESCR: a non-empty, NUL-terminated description string. */
	len = sizeof(value);
	ATF_CHECK_EQ(0, sysctl_op(fixture.session, SYSCTLCMP_OP_DESCR,
	    "kern.ostype", NULL, 0, value, &len));
	ATF_CHECK(len > 0);
	ATF_CHECK_EQ('\0', value[len - 1]);

	/* Both are read gated: a non-permitted name is EPERM. */
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.session, SYSCTLCMP_OP_OIDFMT,
	    "kern.osrelease", NULL, 0, value, &len));
	len = sizeof(value);
	ATF_CHECK_EQ(EPERM, sysctl_op(fixture.session, SYSCTLCMP_OP_DESCR,
	    "kern.osrelease", NULL, 0, value, &len));

	raw_fixture_destroy(&fixture, 0);
}

/*
 * NEXT enumeration filters against the read policy: every name it yields is one
 * the label may read, it surfaces the single permitted variable, and it
 * terminates with ENOENT past the last permitted name -- never leaking a name
 * outside the caller's policy.
 */
ATF_TC(next_never_reveals_denied_names);
ATF_TC_HEAD(next_never_reveals_denied_names, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "NEXT enumerates only policy-permitted names and ends with ENOENT");
}
ATF_TC_BODY(next_never_reveals_denied_names, tc)
{
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	char name[SYSCTLCMP_MAX_NAME];
	uint8_t value[SYSCTLCMP_MAX_NAME];
	size_t len, iterations;
	bool saw_ostype;
	int status;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	name[0] = '\0';
	saw_ostype = false;
	for (iterations = 0; iterations < 64; iterations++) {
		len = sizeof(value);
		status = sysctl_op(fixture.session, SYSCTLCMP_OP_NEXT, name,
		    NULL, 0, value, &len);
		if (status == ENOENT)
			break;			/* enumeration exhausted */
		ATF_REQUIRE_EQ_MSG(0, status, "NEXT failed: %s",
		    strerror(status));
		ATF_REQUIRE(len > 0 && len <= sizeof(value));
		ATF_REQUIRE_EQ('\0', value[len - 1]);
		/* Every yielded name must be permitted by the read policy. */
		ATF_CHECK_MSG(sysctlcmp_config_permits(&config, TEST_LABEL,
		    (const char *)value, false),
		    "NEXT leaked non-permitted name \"%s\"", (const char *)value);
		if (strcmp((const char *)value, "kern.ostype") == 0)
			saw_ostype = true;
		strlcpy(name, (const char *)value, sizeof(name));
	}
	ATF_CHECK(status == ENOENT);
	ATF_CHECK(saw_ostype);

	raw_fixture_destroy(&fixture, 0);
}

/*
 * The provider fails closed on a malformed request: a bad magic fails
 * validation, so handle_request() records EPROTO as a terminal session error
 * and tears the session down without a reply (the call fails and the worker
 * exits non-zero) rather than acting on the frame.
 */
ATF_TC(malformed_request_fails_closed);
ATF_TC_HEAD(malformed_request_fails_closed, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "A malformed request is rejected fail-closed (EPROTO, session torn down)");
}
ATF_TC_BODY(malformed_request_fails_closed, tc)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct sysctlcmp_config config;
	struct raw_fixture fixture;
	struct service_message outgoing;
	struct service_reply incoming;
	struct sysctlcmp_msg msg;
	uint8_t reply[SYSCTLCMP_MAX_MESSAGE];
	int status;

	require_plane();
	make_config(&config);
	raw_fixture_create(&fixture, TEST_LABEL, &config);

	/* A header with a corrupted magic: sysctlcmp_validate_message rejects it. */
	memset(&msg, 0, sizeof(msg));
	msg.magic = SYSCTLCMP_MAGIC ^ 0xffU;
	msg.version = SYSCTLCMP_ABI_VERSION;
	msg.opcode = SYSCTLCMP_OP_HELLO;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &msg;
	outgoing.length = sizeof(msg);
	memset(reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	/* No reply is sent for a rejected frame; the call fails as the session dies. */
	status = service_session_call(fixture.session, &outgoing, &incoming,
	    &options);
	ATF_CHECK_EQ(-1, status);

	/* handle_request set session->error = EPROTO, so the worker exits 1. */
	raw_fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct sysctlcmp_config config;

	make_config(&config);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(-1, TEST_LABEL, &config)
	    == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, NULL, &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, "", &config) == -1);
	ATF_CHECK_ERRNO(EINVAL, sysctlcmp_test_serve(0, TEST_LABEL, NULL) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, policy_gated_get_and_set);
	ATF_TP_ADD_TC(tp, introspection_is_gated);
	ATF_TP_ADD_TC(tp, next_never_reveals_denied_names);
	ATF_TP_ADD_TC(tp, malformed_request_fails_closed);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
