/*- SPDX-License-Identifier: BSD-2-Clause */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/cryptodesc.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <opencrypto/cryptodev.h>

#include <libservice.h>
#include <cryptocmp_protocol.h>

#include "localcrypto_test.h"

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
	fd = open("/dev/crypto", O_RDWR);
	if (fd < 0)
		atf_tc_skip("cryptodev /dev/crypto unavailable: %s",
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
 * Stand up an owner-scoped provider worker bound to a caller-supplied owner
 * label.  Each fixture is a distinct worker sharing the one kernel named-key
 * store, so keys minted under one label are invisible to another.
 */
static void
raw_fixture_create(struct raw_fixture *fixture, const char *owner)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(localcrypto_test_serve(provider, owner));
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

static void
raw_fixture_destroy_any(struct raw_fixture *fixture)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
}

/*
 * Send a well-formed named-key request and return the daemon's errno-style
 * status (0 on success, positive errno on rejection).  On a successful lease the
 * delivered descriptor is returned through out_fd.
 */
static int
named_op(struct raw_fixture *fixture, uint16_t opcode, const void *payload,
    size_t paylen, uint64_t *generation, int *out_fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_msg msg;
	struct cryptocmp_named_reply reply;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_named_create)];
	int fd;

	ATF_REQUIRE(paylen <= sizeof(request) - sizeof(msg));
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = opcode;
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), payload, paylen);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(msg) + paylen;
	fd = -1;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	if (out_fd != NULL) {
		incoming.fds = &fd;
		incoming.fd_capacity = 1;
	}
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0, service_session_call(fixture->session, &outgoing,
	    &incoming, &options));
	if (out_fd != NULL)
		*out_fd = fd;
	if (generation != NULL)
		*generation = reply.generation;
	return (-reply.msg.status);
}

/* Send an arbitrary (possibly malformed) request; return service_session_call's
 * result and, when a reply arrives, its errno-style status. */
static int
send_raw(struct service_session *session, const void *data, size_t length,
    int attach_fd, int *status)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct cryptocmp_named_reply reply;
	int rc, fd;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (attach_fd >= 0) {
		fd = attach_fd;
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	rc = service_session_call(session, &outgoing, &incoming, &options);
	if (rc == 0 && status != NULL)
		*status = -reply.msg.status;
	return (rc);
}

/* A documented, policy-valid symmetric profile for a named key. */
static struct cryptocmp_generate
sample_generate(void)
{
	struct cryptocmp_generate generate;

	memset(&generate, 0, sizeof(generate));
	generate.cipher = CRYPTO_AES_CBC;
	generate.keylen = 32;
	generate.rights = CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT;
	generate.crid = CRYPTO_FLAG_SOFTWARE;
	generate.ivlen = 16;
	generate.maclen = 0;
	return (generate);
}

/*
 * Crown-jewel isolation regression: named keys are scoped to the owner label
 * bound to the unforgeable channel identity.  A key minted by one owner label is
 * invisible to a session running under a different label — lease/rotate/delete
 * fail closed (ENOENT, the kernel key store's owner-scoped miss) — while the
 * owning label reaches its own key.
 */
ATF_TC(named_key_is_owner_scoped);
ATF_TC_HEAD(named_key_is_owner_scoped, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "A named key is reachable only under the owner label that minted it");
}
ATF_TC_BODY(named_key_is_owner_scoped, tc)
{
	struct cryptocmp_named_create create;
	struct cryptocmp_named_lease lease;
	struct cryptocmp_named_control control;
	struct raw_fixture owner_a, owner_b;
	uint64_t generation;
	int fd;

	require_plane();
	raw_fixture_create(&owner_a, "org.test.owner.a");
	raw_fixture_create(&owner_b, "org.test.owner.b");

	/* owner A mints a named key. */
	memset(&create, 0, sizeof(create));
	strlcpy(create.name, "owner-scope-regress.1", sizeof(create.name));
	create.generate = sample_generate();
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_CREATE, &create,
	    sizeof(create), &generation, NULL));

	/* owner B cannot lease, rotate, or delete A's key: owner-scoped miss. */
	memset(&lease, 0, sizeof(lease));
	strlcpy(lease.name, "owner-scope-regress.1", sizeof(lease.name));
	lease.rights = CRYPTODESC_RIGHT_ENCRYPT;
	lease.ttl = 60;
	fd = -1;
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_LEASE, &lease,
	    sizeof(lease), NULL, &fd));
	ATF_CHECK_EQ(-1, fd);

	memset(&control, 0, sizeof(control));
	strlcpy(control.name, "owner-scope-regress.1", sizeof(control.name));
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_ROTATE,
	    &control, sizeof(control), NULL, NULL));
	ATF_CHECK_EQ(ENOENT, named_op(&owner_b, CRYPTOCMP_OP_NAMED_DELETE,
	    &control, sizeof(control), NULL, NULL));

	/* owner A reaches its own key: lease returns a descriptor, then rotate
	 * and delete succeed. */
	fd = -1;
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_LEASE, &lease,
	    sizeof(lease), &generation, &fd));
	ATF_CHECK(fd >= 0);
	if (fd >= 0)
		close(fd);
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_ROTATE, &control,
	    sizeof(control), &generation, NULL));
	ATF_CHECK_EQ(0, named_op(&owner_a, CRYPTOCMP_OP_NAMED_DELETE, &control,
	    sizeof(control), &generation, NULL));

	raw_fixture_destroy(&owner_b, 0);
	raw_fixture_destroy(&owner_a, 0);
}

/*
 * The provider fails closed on malformed requests: a bad magic/version, an
 * out-of-range opcode, a length that does not match the opcode, and any attached
 * descriptor (the handler requires a zero fd count) are all rejected with EPROTO
 * rather than reaching the crypto control device.
 */
ATF_TC(malformed_request_is_rejected);
ATF_TC_HEAD(malformed_request_is_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Malformed crypto requests are rejected fail-closed with EPROTO");
}
ATF_TC_BODY(malformed_request_is_rejected, tc)
{
	struct raw_fixture fixture, attach;
	struct cryptocmp_msg msg;
	struct cryptocmp_generate generate;
	uint8_t request[sizeof(struct cryptocmp_msg) +
	    sizeof(struct cryptocmp_generate)];
	int status, rc, pipefd[2];

	require_plane();
	raw_fixture_create(&fixture, "org.test.malformed");
	generate = sample_generate();

	/* Wrong protocol version. */
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION + 1;
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memset(request, 0, sizeof(request));
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &generate, sizeof(generate));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Out-of-range opcode. */
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = 99;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(request), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	/* Valid opcode, but a truncated body (header only). */
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memcpy(request, &msg, sizeof(msg));
	status = 0;
	ATF_CHECK_EQ(0, send_raw(fixture.session, request, sizeof(msg), -1,
	    &status));
	ATF_CHECK_EQ(EPROTO, status);

	raw_fixture_destroy(&fixture, 0);

	/*
	 * An attached descriptor on an otherwise-valid request must not be
	 * interpreted.  The handler requires fd_count == 0 and replies EPROTO;
	 * on a fresh session so a terminal channel policy cannot mask the check.
	 */
	raw_fixture_create(&attach, "org.test.malformed.fd");
	ATF_REQUIRE_EQ(0, pipe(pipefd));
	memset(&msg, 0, sizeof(msg));
	msg.magic = CRYPTOCMP_MAGIC;
	msg.version = CRYPTOCMP_VERSION;
	msg.opcode = CRYPTOCMP_OP_GENERATE;
	memcpy(request, &msg, sizeof(msg));
	memcpy(request + sizeof(msg), &generate, sizeof(generate));
	status = 0;
	rc = send_raw(attach.session, request, sizeof(request), pipefd[0],
	    &status);
	if (rc == 0)
		ATF_CHECK_EQ(EPROTO, status);
	else
		ATF_CHECK_EQ(-1, rc);
	close(pipefd[0]);
	close(pipefd[1]);
	raw_fixture_destroy_any(&attach);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{

	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(-1, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(0, NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, localcrypto_test_serve(0, "") == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, named_key_is_owner_scoped);
	ATF_TP_ADD_TC(tp, malformed_request_is_rejected);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
