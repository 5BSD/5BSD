/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Plane-level suite for sysextd(8): drive the REAL per-client request handler
 * (sysext_worker -> sysext_request) over a REAL mac_capability channel via the
 * -DSYSEXTD_TESTING serve entry point, and assert the fail-closed reply framing.
 *
 * These cases require the capability plane (/dev/mac_capability + the stack
 * kmods) and root; they skip cleanly where the plane is absent.  None of them
 * exercises the ENSURE happy path, so no kldload(2) ever runs: every case is
 * refused by the allow-list or the message validator before ensure_extension is
 * reached, and we assert only the decision and the reply framing.
 */

#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "sysext_proto.h"
#include "sysextd.h"

struct fixture {
	struct service_session	*session;
	pid_t			 child;
};

static void
require_plane(void)
{
	int fd;

	fd = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (fd == -1)
		atf_tc_skip("mac_capability device unavailable: %s",
		    strerror(errno));
	close(fd);
}

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s", strerror(errno));
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
 * Stand up a worker serving the default (built-in) allow-list on one end of a
 * fresh channel and a client service_session on the other.
 */
static void
fixture_create(struct fixture *fixture)
{
	struct sysext_config cfg;
	int client, provider;

	require_plane();
	sysext_config_defaults(&cfg);
	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		_exit(sysext_test_serve(provider, "test.client", &cfg));
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
	ATF_CHECK(WIFEXITED(status));
}

/*
 * Issue one request and return the reply status.  data/length describe the
 * exact wire bytes to send (so a test can send an intentionally wrong length);
 * fd, when >= 0, is attached to the message.  Requires that a reply arrives.
 */
static int
call_status(struct fixture *fixture, const void *data, size_t length, int fd)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct sysext_reply reply;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = data;
	outgoing.length = length;
	if (fd >= 0) {
		outgoing.fds = &fd;
		outgoing.nfds = 1;
	}
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0,
	    service_session_call(fixture->session, &outgoing, &incoming, &options));
	ATF_REQUIRE_EQ(sizeof(reply), incoming.length);
	return (reply.status);
}

static struct sysext_request
ensure_request(const char *name)
{
	struct sysext_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_ENSURE;
	if (name != NULL)
		strlcpy(rq.name, name, sizeof(rq.name));
	return (rq);
}

/*
 * THE plane-level security regression: an ENSURE for a module that is not on
 * the allow-list is refused with EPERM (fail-closed), never loaded — even though
 * the name is syntactically valid and the client already reached the provider.
 */
ATF_TC(provider_denies_non_allowlisted_module);
ATF_TC_HEAD(provider_denies_non_allowlisted_module, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_denies_non_allowlisted_module, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("evil");
	ATF_CHECK_EQ(EPERM, call_status(&fixture, &rq, sizeof(rq), -1));
	/* Syntactically valid dotted name, still not allow-listed. */
	rq = ensure_request("if_evil.ko");
	ATF_CHECK_EQ(EPERM, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * An unknown opcode is rejected with EINVAL before any load decision.
 */
ATF_TC(provider_rejects_unknown_op);
ATF_TC_HEAD(provider_rejects_unknown_op, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_unknown_op, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("cryptodev");
	rq.op = 0xdead;
	ATF_CHECK_EQ(EINVAL, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * A request whose module name is not NUL-terminated within the wire buffer (an
 * oversized/unterminated name) is rejected with EINVAL — the validator refuses
 * it rather than reading past the field.
 */
ATF_TC(provider_rejects_unterminated_name);
ATF_TC_HEAD(provider_rejects_unterminated_name, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_unterminated_name, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	memset(&rq, 0, sizeof(rq));
	rq.op = SYSEXT_OP_ENSURE;
	memset(rq.name, 'a', sizeof(rq.name));	/* no NUL in the name field */
	ATF_CHECK_EQ(EINVAL, call_status(&fixture, &rq, sizeof(rq), -1));
	fixture_destroy(&fixture);
}

/*
 * A message of the wrong length is malformed and rejected with EPROTO (the
 * length check runs before any name/allow-list decision).
 */
ATF_TC(provider_rejects_wrong_length);
ATF_TC_HEAD(provider_rejects_wrong_length, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_wrong_length, tc)
{
	struct fixture fixture;
	struct sysext_request rq;

	fixture_create(&fixture);
	rq = ensure_request("cryptodev");
	/* Short by one byte: length != sizeof(struct sysext_request). */
	ATF_CHECK_EQ(EPROTO, call_status(&fixture, &rq, sizeof(rq) - 1, -1));
	fixture_destroy(&fixture);
}

/*
 * A request that carries an unexpected descriptor is malformed: sysextd takes
 * no descriptors on this interface, so an attached fd is rejected with EPROTO.
 */
ATF_TC(provider_rejects_attached_descriptor);
ATF_TC_HEAD(provider_rejects_attached_descriptor, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_attached_descriptor, tc)
{
	struct fixture fixture;
	struct sysext_request rq;
	int fd;

	fixture_create(&fixture);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	rq = ensure_request("cryptodev");
	ATF_CHECK_EQ(EPROTO, call_status(&fixture, &rq, sizeof(rq), fd));
	close(fd);
	fixture_destroy(&fixture);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, provider_denies_non_allowlisted_module);
	ATF_TP_ADD_TC(tp, provider_rejects_unknown_op);
	ATF_TP_ADD_TC(tp, provider_rejects_unterminated_name);
	ATF_TP_ADD_TC(tp, provider_rejects_wrong_length);
	ATF_TP_ADD_TC(tp, provider_rejects_attached_descriptor);
	return (atf_no_error());
}
